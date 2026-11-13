#include "broker.h"
#include "config.h"
#include <vector>

namespace zw {

namespace {

struct Pipe {
    HANDLE h = INVALID_HANDLE_VALUE;
    std::string rx;
    ~Pipe() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }

    bool Open() {
        for (int attempt = 0; attempt < 3; attempt++) {
            h = CreateFileW(kBrokerPipe, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
            if (h != INVALID_HANDLE_VALUE) return true;
            if (GetLastError() != ERROR_PIPE_BUSY || !WaitNamedPipeW(kBrokerPipe, 2000)) return false;
        }
        return false;
    }
    bool Write(const std::string& line) {
        std::string s = line + "\n";
        OVERLAPPED ov = {}; ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        DWORD n = 0;
        BOOL ok = WriteFile(h, s.data(), (DWORD)s.size(), nullptr, &ov);
        if (!ok && GetLastError() == ERROR_IO_PENDING) ok = GetOverlappedResult(h, &ov, &n, TRUE);
        CloseHandle(ov.hEvent);
        return ok != FALSE;
    }
    // Reads one line; returns 0 = line, 1 = timeout (poll again), -1 = pipe closed/error.
    int ReadLine(std::string& line, DWORD timeoutMs) {
        for (;;) {
            size_t nl = rx.find('\n');
            if (nl != std::string::npos) { line = rx.substr(0, nl); rx.erase(0, nl + 1); return 0; }
            char buf[512]; DWORD got = 0;
            OVERLAPPED ov = {}; ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            BOOL ok = ReadFile(h, buf, sizeof(buf), nullptr, &ov);
            if (!ok && GetLastError() != ERROR_IO_PENDING) { CloseHandle(ov.hEvent); return -1; }
            if (WaitForSingleObject(ov.hEvent, timeoutMs) == WAIT_TIMEOUT) {
                CancelIo(h); GetOverlappedResult(h, &ov, &got, TRUE); CloseHandle(ov.hEvent);
                if (got) { rx.append(buf, got); continue; }
                return 1;
            }
            ok = GetOverlappedResult(h, &ov, &got, FALSE);
            CloseHandle(ov.hEvent);
            if (!ok || got == 0) return -1;
            rx.append(buf, got);
        }
    }
};

std::wstring Utf8ToW(const std::string& s) { return A2W(s); }

} // namespace

bool BrokerQueryInfo(BrokerInfo& info, std::string* err) {
    Pipe p;
    if (!p.Open()) { if (err) *err = "service not running"; return false; }
    if (!p.Write("INFO")) { if (err) *err = "write"; return false; }
    std::string l;
    if (p.ReadLine(l, 3000) != 0 || l.compare(0, 5, "INFO ") != 0) { if (err) *err = "bad reply: " + l; return false; }
    int en = 0, dbg = 0; char lang[16] = {0};
    sscanf(l.c_str() + 5, "%d %d %15s", &en, &dbg, lang);
    info.enabled = en != 0; info.debug = dbg != 0; info.lang = Utf8ToW(lang);
    std::string user, dom, sid;
    if (p.ReadLine(user, 3000) || p.ReadLine(dom, 3000) || p.ReadLine(sid, 3000)) { if (err) *err = "short reply"; return false; }
    info.user = Utf8ToW(user); info.domain = Utf8ToW(dom); info.sid = Utf8ToW(sid);
    return true;
}

BrokerResult BrokerAuthenticate(std::atomic<bool>& cancel, std::wstring& password, std::string& err,
                                const std::function<void(const std::string&)>& onEvent) {
    Pipe p;
    if (!p.Open()) { err = "service not running"; return BrokerResult::Error; }
    if (!p.Write("AUTH")) { err = "write"; return BrokerResult::Error; }
    std::string l;
    for (;;) {
        if (cancel.load()) { p.Write("CANCEL"); return BrokerResult::Cancelled; }
        int r = p.ReadLine(l, 250);
        if (r == 1) continue;
        if (r < 0) { err = "pipe closed"; return BrokerResult::Error; }
        if (l.compare(0, 3, "EV ") == 0) { if (onEvent) onEvent(l.substr(3)); continue; }
        if (l.compare(0, 3, "PW ") == 0) {
            std::string hex = l.substr(3);
            std::vector<wchar_t> w(hex.size() / 4);
            for (size_t i = 0; i < w.size(); i++) {
                unsigned b0 = 0, b1 = 0;
                sscanf(hex.c_str() + i * 4, "%2x%2x", &b0, &b1);
                w[i] = (wchar_t)(b0 | (b1 << 8));
            }
            password.assign(w.begin(), w.end());
            SecureZeroMemory(&hex[0], hex.size()); SecureZeroMemory(&l[0], l.size());
            if (!w.empty()) SecureZeroMemory(w.data(), w.size() * sizeof(wchar_t));
            return BrokerResult::Password;
        }
        if (l.compare(0, 4, "ERR ") == 0) {
            err = l.substr(4);
            if (err.compare(0, 8, "DISABLED") == 0) return BrokerResult::Disabled;
            if (err.compare(0, 6, "CLIENT") == 0 || err.compare(0, 4, "USER") == 0) return BrokerResult::Refused;
            if (err.compare(0, 8, "NODEVICE") == 0) return BrokerResult::NoDevice;
            if (err.compare(0, 7, "TIMEOUT") == 0) return BrokerResult::Timeout;
            if (err.compare(0, 9, "CANCELLED") == 0) return BrokerResult::Cancelled;
            return BrokerResult::Error;
        }
    }
}

} // namespace zw
