/*
 * ZW111 fingerprint -> Windows Credential Provider token device.
 * Targets (PlatformIO, see platformio.ini):
 *   pico    - Raspberry Pi Pico / any RP2040, Arduino-Pico core (earlephilhower)
 *   esp32s3 - ESP32-S3 with native USB (untested on hardware)
 * Library: "Adafruit Fingerprint Sensor Library" (ZW111 speaks the ZFM/R30x protocol).
 *
 * Wiring (default for RP2040; pins are set in platformio.ini). ZW111 6-pin 1.0 mm connector:
 *   pin 1  V_Touch (3.3V)  -> 3V3
 *   pin 2  TouchOut        -> GP2 (optional, not used by the firmware)
 *   pin 3  VCC (3.3V)      -> 3V3
 *   pin 4  TX              -> GP1 (UART0 RX)
 *   pin 5  RX              -> GP0 (UART0 TX)
 *   pin 6  GND             -> GND
 *
 * Security model (see README):
 *   The device stores K_dev and K_auth (32 bytes each). The PC stores K_pc, K_auth and the
 *   password encrypted with K = SHA256(label || K_dev || K_pc). The device releases K_dev
 *   only after (1) the host proves it knows K_auth for a fresh device nonce and (2) an
 *   enrolled finger matches. Provisioning / enrolling / wiping require the BOOTSEL (or USR) button
 *   to be held, so a program on the PC cannot silently re-key the device or add a finger.
 *
 * Protocol: text lines over USB CDC, 115200 (baud is ignored for USB CDC).
 *   HELLO                         -> OK ZWCP 1 <provisioned 0|1> <templates>
 *   NONCE                         -> NONCE <16 bytes hex>
 *   AUTH <hmac hex 32 bytes>      -> OK WAIT            (host proof = HMAC(K_auth, "zwcp-host-v1"||nonce))
 *                                    then, asynchronously:
 *                                    MATCH <id> <confidence> <wrapped K_dev hex>
 *                                    NOMATCH            (unknown finger, keeps waiting)
 *                                    TIMEOUT            (no finger for AUTH_TIMEOUT_MS)
 *   CANCEL                        -> OK
 *   PROVISION <kdev hex> <kauth hex>  [BOOTSEL]  -> OK PROVISIONED
 *   WIPE                              [BOOTSEL]  -> OK WIPED            (keys + all templates)
 *   ENROLL <id>                       [BOOTSEL]  -> ENROLL PLACE / ENROLL REMOVE / ENROLL AGAIN / OK ENROLL <id>
 *   DELETE <id>                       [BOOTSEL]  -> OK
 *   COUNT                         -> COUNT <n>
 *   Errors: ERR <reason>
 */

#include <Arduino.h>
#include <Adafruit_Fingerprint.h>
#include <EEPROM.h>
#include "sha256.h"

// ---------------- configuration (overridable from platformio.ini build_flags) ----------------
#define SENSOR_SERIAL   Serial1
#ifndef ZW_SENSOR_TX
#define ZW_SENSOR_TX    0        // MCU pin -> sensor RX
#endif
#ifndef ZW_SENSOR_RX
#define ZW_SENSOR_RX    1        // MCU pin <- sensor TX
#endif
#ifndef ZW_SENSOR_BAUD
#define ZW_SENSOR_BAUD  57600
#endif
#ifndef HAS_LED
#define HAS_LED         1        // ZW111 ring LED via command 0x35; set 0 if your module has none
#endif
#define AUTH_TIMEOUT_MS 90000UL  // how long to wait for a finger after AUTH
#define ENROLL_STEP_MS  30000UL

// ---------------- platform glue ----------------
// "Physical presence" check for privileged commands: BOOTSEL on a Pico, a GPIO button elsewhere
// (ZW_PRESENCE_PIN, active low with pull-up).
// On RP2040 the BOOTSEL/BOOT button is always accepted; ZW_PRESENCE_PIN adds a second button
// (e.g. USR on GP24 of the YD-RP2040).
#if defined(ZW_PRESENCE_PIN) && defined(ARDUINO_ARCH_RP2040)
  #define PHYSICAL_PRESENCE() ((bool)BOOTSEL || digitalRead(ZW_PRESENCE_PIN) == LOW)
  static void presenceInit() { pinMode(ZW_PRESENCE_PIN, INPUT_PULLUP); }
#elif defined(ZW_PRESENCE_PIN)
  #define PHYSICAL_PRESENCE() (digitalRead(ZW_PRESENCE_PIN) == LOW)
  static void presenceInit() { pinMode(ZW_PRESENCE_PIN, INPUT_PULLUP); }
#elif defined(ARDUINO_ARCH_RP2040)
  #define PHYSICAL_PRESENCE() ((bool)BOOTSEL)
  static void presenceInit() {}
#else
  #error "Define ZW_PRESENCE_PIN for this board"
#endif

#if defined(ARDUINO_ARCH_RP2040)
  static uint32_t hwRandom32() { return rp2040.hwrand32(); }
  static void sensorSerialPins() { SENSOR_SERIAL.setTX(ZW_SENSOR_TX); SENSOR_SERIAL.setRX(ZW_SENSOR_RX); }
#elif defined(ESP32)
  #include <esp_system.h>
  static uint32_t hwRandom32() { return esp_random(); }
  static void sensorSerialPins() { SENSOR_SERIAL.setPins(ZW_SENSOR_RX, ZW_SENSOR_TX); }
#else
  #error "Unsupported platform: add hwRandom32()/sensorSerialPins() for it"
#endif

// ---------------- persistent storage ----------------
struct Store {
    uint32_t magic;          // 'ZWC1'
    uint8_t  kdev[32];
    uint8_t  kauth[32];
    uint32_t check;          // simple integrity word
};
static const uint32_t kMagic = 0x3143575A; // "ZWC1"
static Store g_store;
static bool  g_provisioned = false;

static uint32_t storeCheck(const Store& s) {
    uint8_t h[32];
    zw::Sha256 c; c.init(); c.update(&s.magic, 4); c.update(s.kdev, 32); c.update(s.kauth, 32); c.finish(h);
    return (uint32_t)h[0] | ((uint32_t)h[1] << 8) | ((uint32_t)h[2] << 16) | ((uint32_t)h[3] << 24);
}
static void loadStore() {
    EEPROM.get(0, g_store);
    g_provisioned = (g_store.magic == kMagic) && (g_store.check == storeCheck(g_store));
    if (!g_provisioned) memset(&g_store, 0, sizeof(g_store));
}
static bool saveStore() {
    g_store.magic = kMagic;
    g_store.check = storeCheck(g_store);
    EEPROM.put(0, g_store);
    return EEPROM.commit();
}
static void wipeStore() {
    memset(&g_store, 0, sizeof(g_store));
    EEPROM.put(0, g_store);
    EEPROM.commit();
    g_provisioned = false;
}

// ---------------- sensor ----------------
Adafruit_Fingerprint finger(&SENSOR_SERIAL);
static bool g_sensorOk = false;

static void ledIdle()  {
#if HAS_LED
    if (g_sensorOk) finger.LEDcontrol(FINGERPRINT_LED_OFF, 0, FINGERPRINT_LED_BLUE);
#endif
}
static void ledWait()  {
#if HAS_LED
    if (g_sensorOk) finger.LEDcontrol(FINGERPRINT_LED_BREATHING, 60, FINGERPRINT_LED_BLUE);
#endif
}
static void ledOk()    {
#if HAS_LED
    if (g_sensorOk) finger.LEDcontrol(FINGERPRINT_LED_ON, 0, FINGERPRINT_LED_BLUE);
#endif
}
static void ledFail()  {
#if HAS_LED
    if (g_sensorOk) finger.LEDcontrol(FINGERPRINT_LED_FLASHING, 10, FINGERPRINT_LED_RED, 3);
#endif
}

static void sensorInit() {
    sensorSerialPins();
    finger.begin(ZW_SENSOR_BAUD);
    delay(50);
    g_sensorOk = finger.verifyPassword();
    if (g_sensorOk) { finger.getParameters(); finger.getTemplateCount(); ledIdle(); }
}

// ---------------- protocol state ----------------
enum State { IDLE, WAITING };
static State    g_state = IDLE;
static uint8_t  g_nonce[16];
static bool     g_nonceValid = false;
static uint32_t g_waitStart = 0;
static uint32_t g_authFailures = 0;

static char g_line[200];
static size_t g_lineLen = 0;

static void sendLine(const char* s) { Serial.print(s); Serial.print("\n"); }
static void sendErr(const char* why) { Serial.print("ERR "); Serial.print(why); Serial.print("\n"); }

static void fillRandom(uint8_t* out, size_t n) {
    for (size_t i = 0; i < n; i += 4) {
        uint32_t r = hwRandom32();
        for (size_t j = 0; j < 4 && i + j < n; j++) out[i + j] = (uint8_t)(r >> (8 * j));
    }
}

static void stopWaiting() {
    g_state = IDLE;
    g_nonceValid = false;
    ledIdle();
}

// Waits for the sensor to see a finger (or no finger), used by ENROLL.
static bool waitImage(bool wantFinger, uint32_t timeoutMs) {
    uint32_t t0 = millis();
    while (millis() - t0 < timeoutMs) {
        uint8_t p = finger.getImage();
        if (wantFinger && p == FINGERPRINT_OK) return true;
        if (!wantFinger && p == FINGERPRINT_NOFINGER) return true;
        delay(30);
    }
    return false;
}

static void cmdEnroll(uint16_t id) {
    if (id < 1 || id >= finger.capacity) { sendErr("BADID"); return; }
    ledWait();
    sendLine("ENROLL PLACE");
    if (!waitImage(true, ENROLL_STEP_MS)) { ledIdle(); sendErr("TIMEOUT"); return; }
    if (finger.image2Tz(1) != FINGERPRINT_OK) { ledFail(); ledIdle(); sendErr("IMAGE1"); return; }
    sendLine("ENROLL REMOVE");
    if (!waitImage(false, ENROLL_STEP_MS)) { ledIdle(); sendErr("TIMEOUT"); return; }
    sendLine("ENROLL AGAIN");
    if (!waitImage(true, ENROLL_STEP_MS)) { ledIdle(); sendErr("TIMEOUT"); return; }
    if (finger.image2Tz(2) != FINGERPRINT_OK) { ledFail(); ledIdle(); sendErr("IMAGE2"); return; }
    uint8_t p = finger.createModel();
    if (p == FINGERPRINT_ENROLLMISMATCH) { ledFail(); ledIdle(); sendErr("MISMATCH"); return; }
    if (p != FINGERPRINT_OK) { ledFail(); ledIdle(); sendErr("MODEL"); return; }
    if (finger.storeModel(id) != FINGERPRINT_OK) { ledFail(); ledIdle(); sendErr("STORE"); return; }
    finger.getTemplateCount();
    ledOk(); delay(400); ledIdle();
    Serial.print("OK ENROLL "); Serial.println(id);
}

static void handleLine(char* line) {
    // tokenize
    char* argv[4] = {0, 0, 0, 0};
    int argc = 0;
    for (char* p = strtok(line, " \t"); p && argc < 4; p = strtok(nullptr, " \t")) argv[argc++] = p;
    if (argc == 0) return;
    const char* cmd = argv[0];

    if (!strcmp(cmd, "HELLO")) {
        Serial.print("OK ZWCP 1 "); Serial.print(g_provisioned ? 1 : 0);
        Serial.print(" "); Serial.println(g_sensorOk ? finger.templateCount : 0);
        return;
    }
    if (!strcmp(cmd, "CANCEL")) { stopWaiting(); sendLine("OK"); return; }
    if (!strcmp(cmd, "COUNT")) {
        if (!g_sensorOk) { sendErr("NOSENSOR"); return; }
        finger.getTemplateCount();
        Serial.print("COUNT "); Serial.println(finger.templateCount);
        return;
    }
    if (!strcmp(cmd, "NONCE")) {
        stopWaiting();
        fillRandom(g_nonce, sizeof(g_nonce));
        g_nonceValid = true;
        char hex[33]; zw::bin2hex(g_nonce, 16, hex);
        Serial.print("NONCE "); Serial.println(hex);
        return;
    }
    if (!strcmp(cmd, "AUTH")) {
        if (!g_provisioned) { sendErr("NOTPROVISIONED"); return; }
        if (!g_sensorOk) { sendErr("NOSENSOR"); return; }
        if (!g_nonceValid || argc < 2) { sendErr("NONCE"); return; }
        uint8_t given[32], expect[32];
        if (!zw::hex2bin(argv[1], given, 32)) { sendErr("FORMAT"); return; }
        zw::host_proof(g_store.kauth, g_nonce, expect);
        if (!zw::ct_equal(given, expect, 32)) {
            g_nonceValid = false;
            g_authFailures++;
            delay(g_authFailures >= 10 ? 10000UL : g_authFailures * 1000UL);   // slow down guessing
            sendErr("AUTH");
            return;
        }
        g_authFailures = 0;
        g_state = WAITING;
        g_waitStart = millis();
        ledWait();
        sendLine("OK WAIT");
        return;
    }

    // ---- privileged commands: need physical presence ----
    bool priv = !strcmp(cmd, "PROVISION") || !strcmp(cmd, "WIPE") || !strcmp(cmd, "ENROLL") || !strcmp(cmd, "DELETE");
    if (priv) {
        if (!PHYSICAL_PRESENCE()) { sendErr("PRESS_BOOTSEL"); return; }
        stopWaiting();
        if (!strcmp(cmd, "PROVISION")) {
            if (argc < 3) { sendErr("FORMAT"); return; }
            Store s; memset(&s, 0, sizeof(s));
            if (!zw::hex2bin(argv[1], s.kdev, 32) || !zw::hex2bin(argv[2], s.kauth, 32)) { sendErr("FORMAT"); return; }
            memcpy(g_store.kdev, s.kdev, 32); memcpy(g_store.kauth, s.kauth, 32);
            memset(&s, 0, sizeof(s));
            if (!saveStore()) { sendErr("FLASH"); return; }
            g_provisioned = true;
            sendLine("OK PROVISIONED");
            return;
        }
        if (!strcmp(cmd, "WIPE")) {
            wipeStore();
            if (g_sensorOk) finger.emptyDatabase();
            sendLine("OK WIPED");
            return;
        }
        if (!g_sensorOk) { sendErr("NOSENSOR"); return; }
        if (!strcmp(cmd, "ENROLL")) {
            if (argc < 2) { sendErr("FORMAT"); return; }
            cmdEnroll((uint16_t)atoi(argv[1]));
            return;
        }
        if (!strcmp(cmd, "DELETE")) {
            if (argc < 2) { sendErr("FORMAT"); return; }
            if (finger.deleteModel((uint16_t)atoi(argv[1])) != FINGERPRINT_OK) { sendErr("DELETE"); return; }
            finger.getTemplateCount();
            sendLine("OK");
            return;
        }
    }
    sendErr("UNKNOWN");
}

// Called every loop() while WAITING: polls the sensor, reports MATCH/NOMATCH/TIMEOUT.
static void pollFinger() {
    if (millis() - g_waitStart > AUTH_TIMEOUT_MS) { stopWaiting(); sendLine("TIMEOUT"); return; }
    uint8_t p = finger.getImage();
    if (p != FINGERPRINT_OK) return;              // no finger yet (or a transient error)
    if (finger.image2Tz() != FINGERPRINT_OK) return;
    p = finger.fingerSearch();
    if (p == FINGERPRINT_OK) {
        uint8_t mask[32], wrapped[32];
        zw::wrap_mask(g_store.kauth, g_nonce, mask);
        for (int i = 0; i < 32; i++) wrapped[i] = g_store.kdev[i] ^ mask[i];
        char hex[65]; zw::bin2hex(wrapped, 32, hex);
        memset(mask, 0, sizeof(mask)); memset(wrapped, 0, sizeof(wrapped));
        uint16_t id = finger.fingerID, conf = finger.confidence;
        stopWaiting();                            // invalidates the nonce: one match per handshake
        ledOk();
        Serial.print("MATCH "); Serial.print(id); Serial.print(" "); Serial.print(conf);
        Serial.print(" "); Serial.println(hex);
        delay(300); ledIdle();
    } else if (p == FINGERPRINT_NOTFOUND) {
        sendLine("NOMATCH");
        ledFail(); delay(600); ledWait();
        // wait until the finger is lifted so one wrong finger does not spam NOMATCH
        waitImage(false, 3000);
    }
}

void setup() {
    Serial.begin(115200);
    presenceInit();
    EEPROM.begin(256);
    loadStore();
    sensorInit();
}

void loop() {
    while (Serial.available()) {
        char c = (char)Serial.read();
        if (c == '\n' || c == '\r') {
            if (g_lineLen > 0) { g_line[g_lineLen] = 0; handleLine(g_line); g_lineLen = 0; }
        } else if (g_lineLen < sizeof(g_line) - 1) {
            g_line[g_lineLen++] = c;
        } else {
            g_lineLen = 0; sendErr("TOOLONG");
        }
    }
    if (g_state == WAITING) pollFinger();
    else if (!g_sensorOk) { static uint32_t last = 0; if (millis() - last > 2000) { last = millis(); sensorInit(); } }
    delay(5);
}
