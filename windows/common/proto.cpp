#include "proto.h"
#include "sha256.h"
#include "config.h"
#include "i18n.h"
#include <sstream>

namespace zw {

static bool Expect(SerialPort& port, const std::string& prefix, std::string& line, DWORD timeoutMs, std::string* err) {
    bool ioErr = false;
    while (port.ReadLine(line, timeoutMs, &ioErr)) {
        if (line.compare(0, prefix.size(), prefix) == 0) return true;
        if (line.compare(0, 4, "ERR ") == 0) { if (err) *err = line; return false; }
        // ignore unrelated lines (e.g. late NOMATCH/TIMEOUT from a previous handshake)
    }
    if (err) *err = ioErr ? "io error" : "timeout waiting for " + prefix + (line.empty() ? "" : ", last line: '" + line + "'");
    return false;
}

bool Hello(SerialPort& port, DeviceInfo& info, std::string* err) {
    port.Purge();
    if (!port.WriteLine("HELLO")) { if (err) *err = "write failed"; return false; }
    std::string line;
    if (!Expect(port, "OK ZWCP ", line, 1500, err)) return false;
    std::istringstream ss(line.substr(8));
    int ver = 0, prov = 0, tmpl = 0; ss >> ver >> prov >> tmpl;
    info.provisioned = prov != 0; info.templates = tmpl;
    return ver == 1;
}

bool OpenDevice(SerialPort& port, const std::wstring& portSetting, const std::wstring& usbId, std::wstring* chosen, std::wstring* diag) {
    std::vector<std::wstring> candidates;
    if (_wcsicmp(portSetting.c_str(), L"auto") == 0) candidates = FindComPortsByUsbId(usbId);
    else candidates.push_back(portSetting);
    if (diag) diag->clear();
    if (candidates.empty() && diag) *diag = Ts(S::NO_PORTS_WITH_ID) + usbId;
    for (auto& c : candidates) {
        if (!port.Open(c)) {
            DWORD e = GetLastError();
            if (diag) {
                *diag += c + T(S::PORT_OPEN_FAILED) + std::to_wstring(e);
                if (e == ERROR_ACCESS_DENIED) *diag += T(S::PORT_BUSY);
                if (e == ERROR_FILE_NOT_FOUND) *diag += T(S::PORT_GONE);
                *diag += L"\n";
            }
            continue;
        }
        DeviceInfo info; std::string err, got;
        // The device may need a moment after the port opens (USB CDC DTR). Try a few times.
        for (int attempt = 0; attempt < 3; attempt++) {
            if (Hello(port, info, &err)) { if (chosen) *chosen = c; return true; }
            if (!err.empty()) got = err;
            Sleep(400);
        }
        if (diag) *diag += c + T(S::PORT_NO_HELLO) + A2W(got) + T(S::PORT_NO_HELLO2) + L"\n";
        port.Close();
    }
    return false;
}

AuthResult RunAuth(SerialPort& port, const uint8_t kauth[32], std::atomic<bool>& cancel,
                   uint8_t kdevOut[32], int& fingerId, std::string* err,
                   const std::function<void(const std::string&)>& onEvent, DWORD waitMs) {
    std::string line;
    port.Purge();
    if (!port.WriteLine("NONCE")) { if (err) *err = "write"; return AuthResult::NoDevice; }
    if (!Expect(port, "NONCE ", line, 2000, err)) return AuthResult::NoDevice;
    uint8_t nonce[16];
    if (line.size() < 6 + 32 || !hex2bin(line.c_str() + 6, nonce, 16)) { if (err) *err = "bad nonce"; return AuthResult::Error; }

    uint8_t proof[32]; char hex[65];
    host_proof(kauth, nonce, proof);
    bin2hex(proof, 32, hex);
    if (!port.WriteLine(std::string("AUTH ") + hex)) { if (err) *err = "write"; return AuthResult::NoDevice; }
    bool ioErr = false;
    for (;;) {
        if (!port.ReadLine(line, 12000, &ioErr)) { if (err) *err = ioErr ? "io error" : "no AUTH reply"; return AuthResult::NoDevice; }
        if (line == "OK WAIT") break;
        if (line == "ERR AUTH") return AuthResult::AuthFailed;
        if (line == "ERR NOTPROVISIONED") return AuthResult::NotProvisioned;
        if (line.compare(0, 4, "ERR ") == 0) { if (err) *err = line; return AuthResult::Error; }
    }
    if (onEvent) onEvent("WAIT");
    ULONGLONG waitStart = GetTickCount64();

    for (;;) {
        if (cancel.load()) { port.WriteLine("CANCEL"); return AuthResult::Cancelled; }
        if (waitMs && GetTickCount64() - waitStart > waitMs) { port.WriteLine("CANCEL"); return AuthResult::Timeout; }
        if (!port.ReadLine(line, 250, &ioErr)) {
            if (ioErr) { if (err) *err = "io error"; return AuthResult::NoDevice; }
            continue;
        }
        if (line.compare(0, 6, "MATCH ") == 0) {
            std::istringstream ss(line.substr(6));
            int id = 0, conf = 0; std::string whex; ss >> id >> conf >> whex;
            uint8_t wrapped[32], mask[32];
            if (whex.size() != 64 || !hex2bin(whex.c_str(), wrapped, 32)) { if (err) *err = "bad MATCH"; return AuthResult::Error; }
            wrap_mask(kauth, nonce, mask);
            for (int i = 0; i < 32; i++) kdevOut[i] = wrapped[i] ^ mask[i];
            SecureZeroMemory(wrapped, 32); SecureZeroMemory(mask, 32);
            fingerId = id;
            return AuthResult::Match;
        }
        if (line == "NOMATCH") { if (onEvent) onEvent("NOMATCH"); continue; }
        if (line == "TIMEOUT") return AuthResult::Timeout;
        if (line.compare(0, 4, "ERR ") == 0) { if (err) *err = line; return AuthResult::Error; }
    }
}

bool Provision(SerialPort& port, const uint8_t kdev[32], const uint8_t kauth[32], std::string* err) {
    char h1[65], h2[65]; bin2hex(kdev, 32, h1); bin2hex(kauth, 32, h2);
    port.Purge();
    if (!port.WriteLine(std::string("PROVISION ") + h1 + " " + h2)) { if (err) *err = "write"; return false; }
    SecureZeroMemory(h1, sizeof(h1)); SecureZeroMemory(h2, sizeof(h2));
    std::string line;
    return Expect(port, "OK PROVISIONED", line, 5000, err);
}

bool Wipe(SerialPort& port, std::string* err) {
    port.Purge();
    if (!port.WriteLine("WIPE")) { if (err) *err = "write"; return false; }
    std::string line;
    return Expect(port, "OK WIPED", line, 10000, err);
}

bool Enroll(SerialPort& port, int id, const std::function<void(const std::string&)>& onEvent, std::string* err) {
    port.Purge();
    if (!port.WriteLine("ENROLL " + std::to_string(id))) { if (err) *err = "write"; return false; }
    std::string line; bool ioErr = false;
    ULONGLONG deadline = GetTickCount64() + 120000;
    while (GetTickCount64() < deadline) {
        if (!port.ReadLine(line, 1000, &ioErr)) { if (ioErr) { if (err) *err = "io error"; return false; } continue; }
        if (line.compare(0, 7, "ENROLL ") == 0) { if (onEvent) onEvent(line.substr(7)); continue; }
        if (line.compare(0, 10, "OK ENROLL ") == 0) return true;
        if (line.compare(0, 4, "ERR ") == 0) { if (err) *err = line; return false; }
    }
    if (err) *err = "timeout";
    return false;
}

bool DeleteFinger(SerialPort& port, int id, std::string* err) {
    port.Purge();
    if (!port.WriteLine("DELETE " + std::to_string(id))) { if (err) *err = "write"; return false; }
    std::string line;
    return Expect(port, "OK", line, 5000, err);
}

} // namespace zw
