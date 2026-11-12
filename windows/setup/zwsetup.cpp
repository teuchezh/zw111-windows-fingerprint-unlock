// zwsetup: provisioning / enrollment / diagnostics for ZwCredProv (console). Run as Administrator.
#include <windows.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <atomic>
#include <conio.h>
#include <io.h>
#include <fcntl.h>
#include "../common/config.h"
#include "../common/proto.h"
#include "../common/sha256.h"
#include "../common/i18n.h"

using namespace zw;

static void usage() {
    if (CurrentLang() == Lang::Ru) wprintf(
L"zwsetup — настройка входа в Windows по отпечатку (ZW111 + RP2040)\n\n"
L"  zwsetup provision --user ИМЯ [--domain ДОМЕН|.] [--port COMn|auto] [--usbid VID_xxxx&PID_xxxx] [--finger N] [--debug] [--lang auto|ru|en]\n"
L"        Полная настройка: новые ключи, запись ключей в устройство (держите USR/BOOT!),\n"
L"        запрос пароля и запись зашифрованной конфигурации в реестр.\n"
L"  zwsetup enroll --id N [--port COMn|auto]       Записать палец в слот N (держите USR/BOOT)\n"
L"  zwsetup delete --id N [--port COMn|auto]       Удалить палец из слота N (держите USR/BOOT)\n"
L"  zwsetup test [--port COMn|auto]                Проверить всю цепочку без входа в систему\n"
L"  zwsetup set-password [--port COMn|auto]        Сменить сохранённый пароль (нужен палец)\n"
L"  zwsetup status                                  Показать конфигурацию и найти устройство\n"
L"  zwsetup wipe [--port COMn|auto]                 Стереть ключи и все отпечатки в устройстве\n"
L"  zwsetup disable | enable                        Временно выключить/включить плитку входа\n"
L"  zwsetup lang auto|ru|en                         Язык плитки и утилит\n"
L"  zwsetup uninstall                               Удалить конфигурацию из реестра\n");
    else wprintf(
L"zwsetup — fingerprint sign-in for Windows (ZW111 + RP2040)\n\n"
L"  zwsetup provision --user NAME [--domain DOMAIN|.] [--port COMn|auto] [--usbid VID_xxxx&PID_xxxx] [--finger N] [--debug] [--lang auto|ru|en]\n"
L"        Full setup: new keys, keys written to the device (hold USR/BOOT!),\n"
L"        password prompt and encrypted configuration in the registry.\n"
L"  zwsetup enroll --id N [--port COMn|auto]       Enroll a finger into slot N (hold USR/BOOT)\n"
L"  zwsetup delete --id N [--port COMn|auto]       Delete the finger in slot N (hold USR/BOOT)\n"
L"  zwsetup test [--port COMn|auto]                Test the whole chain without signing in\n"
L"  zwsetup set-password [--port COMn|auto]        Change the stored password (finger required)\n"
L"  zwsetup status                                  Show the configuration and find the device\n"
L"  zwsetup wipe [--port COMn|auto]                 Erase keys and all fingerprints in the device\n"
L"  zwsetup disable | enable                        Temporarily hide/show the sign-in tile\n"
L"  zwsetup lang auto|ru|en                         Language of the tile and the tools\n"
L"  zwsetup uninstall                               Remove the configuration from the registry\n");
}

static std::wstring Arg(int argc, wchar_t** argv, const wchar_t* name, const wchar_t* def = L"") {
    for (int i = 1; i + 1 < argc; i++) if (_wcsicmp(argv[i], name) == 0) return argv[i + 1];
    return def;
}
static bool Flag(int argc, wchar_t** argv, const wchar_t* name) {
    for (int i = 1; i < argc; i++) if (_wcsicmp(argv[i], name) == 0) return true;
    return false;
}

static std::wstring ReadPassword(const wchar_t* prompt) {
    wprintf(L"%ls", prompt); fflush(stdout);
    std::wstring s;
    for (;;) {
        wint_t c = _getwch();
        if (c == L'\r' || c == L'\n') break;
        if (c == 8) { if (!s.empty()) { s.pop_back(); wprintf(L"\b \b"); } continue; }
        if (c == 3) { wprintf(L"\n"); exit(1); }
        if (c == 0 || c == 0xE0) { _getwch(); continue; }   // function keys
        s.push_back((wchar_t)c); wprintf(L"*");
    }
    wprintf(L"\n");
    return s;
}

static bool OpenCfgDevice(SerialPort& port, const Config& cfg, const std::wstring& portOverride) {
    std::wstring chosen, diag;
    std::wstring p = portOverride.empty() ? cfg.port : portOverride;
    if (!OpenDevice(port, p, cfg.usbId, &chosen, &diag)) {
        wprintf(T(S::DEVICE_NOT_FOUND), p.c_str(), cfg.usbId.c_str());
        wprintf(L"\n%ls", diag.c_str());
        return false;
    }
    wprintf(L"%ls%ls\n", T(S::DEVICE_FOUND_ON), chosen.c_str());
    return true;
}

static void PrintAuthResult(AuthResult r, const std::string& err) {
    switch (r) {
    case AuthResult::Match: break;
    case AuthResult::NoDevice: wprintf(L"%ls%ls\n", T(S::ERR_COMM), A2W(err).c_str()); break;
    case AuthResult::NotProvisioned: wprintf(L"%ls\n", T(S::ERR_NOT_PROVISIONED)); break;
    case AuthResult::AuthFailed: wprintf(L"%ls\n", T(S::ERR_AUTH_FAILED)); break;
    case AuthResult::Timeout: wprintf(L"%ls\n", T(S::ERR_TIMEOUT)); break;
    case AuthResult::Cancelled: break;
    case AuthResult::Error: wprintf(L"%ls%ls\n", T(S::ERR_PROTOCOL), A2W(err).c_str()); break;
    }
}

static bool AuthGetKdev(SerialPort& port, const Secrets& s, uint8_t kdev[32]) {
    std::atomic<bool> cancel{false}; int id = 0; std::string err;
    AuthResult r = RunAuth(port, s.kauth, cancel, kdev, id, &err, [](const std::string& ev) {
        if (ev == "WAIT") wprintf(L"%ls\n", T(S::PLACE_FINGER));
        else if (ev == "NOMATCH") wprintf(L"%ls\n", T(S::NOMATCH_RETRY));
    });
    PrintAuthResult(r, err);
    if (r != AuthResult::Match) return false;
    wprintf(L"%ls%d\n", T(S::MATCH_ID), id);
    return true;
}

static int CmdProvision(int argc, wchar_t** argv) {
    Config cfg; LoadConfig(cfg);     // keep existing port/usbId/lang if any
    std::wstring user = Arg(argc, argv, L"--user");
    if (user.empty()) { wprintf(L"%ls\n", T(S::CLI_NEED_USER)); return 2; }
    cfg.user = user;
    cfg.domain = Arg(argc, argv, L"--domain", L".");
    std::wstring port = Arg(argc, argv, L"--port"); if (!port.empty()) cfg.port = port;
    std::wstring usb = Arg(argc, argv, L"--usbid"); if (!usb.empty()) cfg.usbId = usb;
    std::wstring lang = Arg(argc, argv, L"--lang"); if (!lang.empty()) { cfg.lang = lang; SetLangFromSetting(lang); }
    cfg.fingerId = _wtoi(Arg(argc, argv, L"--finger", L"0").c_str());
    cfg.debug = Flag(argc, argv, L"--debug");
    cfg.enabled = true;

    std::wstring email;
    if (cfg.domain == L"." && LinkedMicrosoftAccount(cfg.user, email)) {
        wprintf(T(S::MSA_CLI_USING), cfg.user.c_str(), email.c_str(), email.c_str());
        cfg.domain = L"MicrosoftAccount"; cfg.user = email;
    }
    if (_wcsicmp(cfg.domain.c_str(), L"MicrosoftAccount") == 0 && cfg.user.find(L'@') == std::wstring::npos)
        wprintf(L"%ls\n", T(S::MSA_NEEDS_EMAIL));

    std::wstring qualified = EffectiveDomain(cfg) + L"\\" + cfg.user;
    BYTE sid[SECURITY_MAX_SID_SIZE]; DWORD cb = sizeof(sid); wchar_t dom[256]; DWORD cd = 256; SID_NAME_USE use;
    if (!LookupAccountNameW(nullptr, qualified.c_str(), sid, &cb, dom, &cd, &use)) wprintf(T(S::CLI_ACCOUNT_WARN), qualified.c_str());
    else wprintf(L"%ls%ls\n", T(S::ACCOUNT_IS), qualified.c_str());

    SerialPort dev;
    if (!OpenCfgDevice(dev, cfg, L"")) { wprintf(L"%ls\n", T(S::CLI_PLUG_DEVICE)); return 1; }

    std::wstring pw = ReadPassword(T(S::CLI_PW_PROMPT));
    std::wstring pw2 = ReadPassword(T(S::CLI_PW_REPEAT));
    if (pw != pw2) { wprintf(L"%ls\n", T(S::ERR_PW_MISMATCH)); return 1; }

    Secrets s; uint8_t kdev[32];
    if (!RandomBytes(kdev, 32) || !RandomBytes(s.kpc, 32) || !RandomBytes(s.kauth, 32)) { wprintf(L"%ls\n", T(S::ERR_RNG)); return 1; }

    wprintf(L"\n%ls", T(S::HOLD_BUTTON_ENTER));
    getwchar();
    std::string err;
    if (!Provision(dev, kdev, s.kauth, &err)) {
        wprintf(L"%ls%ls%ls\n", T(S::DEVICE_REFUSED), A2W(err).c_str(), T(S::BUTTON_HELD_Q));
        SecureZeroMemory(kdev, 32); return 1;
    }
    wprintf(L"%ls\n", T(S::KEYS_WRITTEN));

    if (!SealPassword(s, kdev, pw)) { wprintf(L"%ls\n", T(S::ERR_ENCRYPT)); SecureZeroMemory(kdev, 32); return 1; }
    SecureZeroMemory(kdev, 32);
    SecureZeroMemory(&pw[0], pw.size() * 2); SecureZeroMemory(&pw2[0], pw2.size() * 2);

    std::wstring werr;
    if (!ProtectSecrets(s, cfg.blob, &werr) || !SaveConfig(cfg, &werr)) { wprintf(L"%ls%ls\n", T(S::ERR_SAVE_CFG), werr.c_str()); return 1; }
    wprintf(T(S::CLI_CFG_SAVED_AT), kRegPath);

    DeviceInfo info; Hello(dev, info);
    if (info.templates == 0) wprintf(L"%ls", T(S::CLI_NO_TEMPLATES));
    else wprintf(T(S::CLI_TEMPLATES_TEST), info.templates);
    wprintf(L"%ls\n", T(S::DLL_NOT_REG_CLI));
    return 0;
}

static int CmdEnroll(int argc, wchar_t** argv, bool del) {
    Config cfg; LoadConfig(cfg);
    int id = _wtoi(Arg(argc, argv, L"--id", L"0").c_str());
    if (id <= 0 || id > 199) { wprintf(L"%ls\n", T(S::CLI_NEED_ID)); return 2; }
    SerialPort dev;
    if (!OpenCfgDevice(dev, cfg, Arg(argc, argv, L"--port"))) return 1;
    wprintf(L"%ls", T(S::HOLD_BUTTON_ENTER));
    getwchar();
    std::string err;
    if (del) {
        if (!DeleteFinger(dev, id, &err)) { wprintf(L"%ls%ls\n", T(S::DELETE_ERR), A2W(err).c_str()); return 1; }
        wprintf(L"%ls%d%ls\n", T(S::SLOT_DELETED_A), id, T(S::SLOT_DELETED_B)); return 0;
    }
    bool ok = Enroll(dev, id, [](const std::string& ev) {
        if (ev == "PLACE") wprintf(L"%ls\n", T(S::ENROLL_PLACE));
        else if (ev == "REMOVE") wprintf(L"%ls\n", T(S::ENROLL_REMOVE));
        else if (ev == "AGAIN") wprintf(L"%ls\n", T(S::ENROLL_AGAIN));
    }, &err);
    if (!ok) { wprintf(L"%ls%ls\n", T(S::ENROLL_ERR), A2W(err).c_str()); return 1; }
    wprintf(L"%ls%d.\n", T(S::ENROLLED_SLOT), id);
    return 0;
}

static int CmdTest(int argc, wchar_t** argv) {
    Config cfg; std::wstring werr;
    if (!LoadConfig(cfg, &werr)) { wprintf(L"%ls\n", werr.c_str()); return 1; }
    Secrets s;
    if (!UnprotectSecrets(cfg.blob, s, &werr)) { wprintf(L"%ls%ls\n", T(S::ERR_UNPROTECT), werr.c_str()); return 1; }
    SerialPort dev;
    if (!OpenCfgDevice(dev, cfg, Arg(argc, argv, L"--port"))) return 1;
    uint8_t kdev[32];
    if (!AuthGetKdev(dev, s, kdev)) return 1;
    std::wstring pw;
    bool ok = OpenPassword(s, kdev, pw);
    SecureZeroMemory(kdev, 32);
    if (!ok) { wprintf(L"%ls\n", T(S::PW_NOT_DECRYPTED)); return 1; }
    wprintf(T(S::CLI_PW_LEN), (unsigned)pw.size());
    HANDLE tok = nullptr;
    std::wstring dom = EffectiveDomain(cfg);
    if (LogonUserW(cfg.user.c_str(), dom.c_str(), pw.c_str(), LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &tok)) {
        wprintf(L"%ls\n", T(S::LOGON_OK)); CloseHandle(tok);
    } else {
        wprintf(L"%ls%lu%ls\n", T(S::LOGON_FAIL_A), GetLastError(), T(S::LOGON_FAIL_B));
        std::wstring email;
        if (cfg.domain == L"." && LinkedMicrosoftAccount(cfg.user, email))
            wprintf(L"%ls%ls%ls%ls%ls%ls%ls\n", T(S::MSA_LINKED_A), cfg.user.c_str(), T(S::MSA_LINKED_B), email.c_str(), T(S::MSA_LINKED_FIX), email.c_str(), T(S::MSA_LINKED_FIX2));
        else wprintf(L"%ls\n", T(S::PW_HINT));
    }
    SecureZeroMemory(&pw[0], pw.size() * 2);
    return 0;
}

static int CmdSetPassword(int argc, wchar_t** argv) {
    Config cfg; std::wstring werr;
    if (!LoadConfig(cfg, &werr)) { wprintf(L"%ls\n", werr.c_str()); return 1; }
    Secrets s;
    if (!UnprotectSecrets(cfg.blob, s, &werr)) { wprintf(L"%ls%ls\n", T(S::ERR_UNPROTECT), werr.c_str()); return 1; }
    SerialPort dev;
    if (!OpenCfgDevice(dev, cfg, Arg(argc, argv, L"--port"))) return 1;
    std::wstring pw = ReadPassword(T(S::CLI_PW_NEW));
    std::wstring pw2 = ReadPassword(T(S::CLI_PW_REPEAT));
    if (pw != pw2) { wprintf(L"%ls\n", T(S::ERR_PW_MISMATCH)); return 1; }
    uint8_t kdev[32];
    if (!AuthGetKdev(dev, s, kdev)) return 1;
    bool ok = SealPassword(s, kdev, pw);
    SecureZeroMemory(kdev, 32); SecureZeroMemory(&pw[0], pw.size() * 2); SecureZeroMemory(&pw2[0], pw2.size() * 2);
    if (!ok || !ProtectSecrets(s, cfg.blob, &werr) || !SaveConfig(cfg, &werr)) { wprintf(L"%ls%ls\n", T(S::CLI_ERROR), werr.c_str()); return 1; }
    wprintf(L"%ls\n", T(S::PW_UPDATED));
    return 0;
}

static int CmdStatus() {
    Config cfg; std::wstring werr;
    bool ok = LoadConfig(cfg, &werr);
    wprintf(L"%ls%ls\n", T(S::CLI_STATUS_CFG), ok ? L"OK" : werr.c_str());
    if (ok) wprintf(L"  User=%ls Domain=%ls (%ls) Port=%ls UsbId=%ls FingerId=%lu Enabled=%d Debug=%d Lang=%ls\n",
        cfg.user.c_str(), cfg.domain.c_str(), EffectiveDomain(cfg).c_str(), cfg.port.c_str(), cfg.usbId.c_str(), cfg.fingerId, (int)cfg.enabled, (int)cfg.debug, cfg.lang.c_str());
    auto all = ListComPorts();
    wprintf(L"%ls%ls\n", T(S::CLI_STATUS_ALL_PORTS), all.empty() ? T(S::CLI_NONE) : L"");
    for (auto& p : all) wprintf(L"  %-6ls %ls\n", p.first.c_str(), p.second.c_str());
    auto ports = FindComPortsByUsbId(cfg.usbId);
    wprintf(T(S::CLI_PORTS_WITH_ID), cfg.usbId.c_str(), ports.empty() ? T(S::CLI_NO) : L"");
    for (auto& p : ports) wprintf(L"  %ls\n", p.c_str());
    if (ports.empty() && !all.empty()) wprintf(L"%ls", T(S::CLI_PORT_HINT));
    SerialPort dev; std::wstring chosen, diag;
    if (OpenDevice(dev, cfg.port, cfg.usbId, &chosen, &diag)) {
        DeviceInfo info; Hello(dev, info);
        wprintf(T(S::CLI_DEVICE_ON), chosen.c_str(), (int)info.provisioned, info.templates);
    } else wprintf(L"%ls%ls", T(S::CLI_DEVICE_SILENT), diag.c_str());
    HKEY k;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\{7B2F3C1E-9A4D-4E6B-8C21-5D0E9F3A6B47}", 0, KEY_READ | KEY_WOW64_64KEY, &k) == ERROR_SUCCESS) {
        wprintf(L"%ls", T(S::CLI_DLL_REG)); RegCloseKey(k);
    } else wprintf(L"%ls", T(S::CLI_DLL_NOT_REG));
    return 0;
}

static int CmdEnable(bool on) {
    Config cfg; std::wstring werr;
    if (!LoadConfig(cfg, &werr)) { wprintf(L"%ls\n", werr.c_str()); return 1; }
    cfg.enabled = on;
    if (!SaveConfig(cfg, &werr)) { wprintf(L"%ls\n", werr.c_str()); return 1; }
    wprintf(L"%ls\n", on ? T(S::TILE_ON) : T(S::TILE_OFF)); return 0;
}

static int CmdLang(int argc, wchar_t** argv) {
    Config cfg; std::wstring werr;
    if (!LoadConfig(cfg, &werr)) { wprintf(L"%ls\n", werr.c_str()); return 1; }
    cfg.lang = argc > 2 ? argv[2] : L"auto";
    if (!SaveConfig(cfg, &werr)) { wprintf(L"%ls\n", werr.c_str()); return 1; }
    SetLangFromSetting(cfg.lang);
    wprintf(L"%ls%ls\n", T(S::CLI_LANG_SET), cfg.lang.c_str()); return 0;
}

static int CmdWipe(int argc, wchar_t** argv) {
    Config cfg; LoadConfig(cfg);
    SerialPort dev;
    if (!OpenCfgDevice(dev, cfg, Arg(argc, argv, L"--port"))) return 1;
    wprintf(L"%ls", T(S::WIPE_CONFIRM_CLI));
    getwchar();
    std::string err;
    if (!Wipe(dev, &err)) { wprintf(L"%ls%ls\n", T(S::CLI_ERROR), A2W(err).c_str()); return 1; }
    wprintf(L"%ls\n", T(S::WIPED)); return 0;
}

int wmain(int argc, wchar_t** argv) {
    _setmode(_fileno(stdout), _O_U16TEXT);
    { Config cfg; LoadConfig(cfg); }                       // applies the saved Lang
    std::wstring lang = Arg(argc, argv, L"--lang"); if (!lang.empty()) SetLangFromSetting(lang);
    if (argc < 2) { usage(); return 2; }
    std::wstring cmd = argv[1];
    if (cmd == L"provision") return CmdProvision(argc, argv);
    if (cmd == L"enroll") return CmdEnroll(argc, argv, false);
    if (cmd == L"delete") return CmdEnroll(argc, argv, true);
    if (cmd == L"test") return CmdTest(argc, argv);
    if (cmd == L"set-password") return CmdSetPassword(argc, argv);
    if (cmd == L"status") return CmdStatus();
    if (cmd == L"enable") return CmdEnable(true);
    if (cmd == L"disable") return CmdEnable(false);
    if (cmd == L"lang") return CmdLang(argc, argv);
    if (cmd == L"wipe") return CmdWipe(argc, argv);
    if (cmd == L"uninstall") { wprintf(L"%ls", DeleteConfig() ? T(S::CLI_UNINSTALLED) : T(S::NOTHING_TO_DELETE)); wprintf(L"\n"); return 0; }
    usage(); return 2;
}
