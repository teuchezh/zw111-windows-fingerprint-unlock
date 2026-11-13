// ZwCredSvc: SYSTEM service that lets the credential provider sign in from Windows Security prompts (CredUI).
// In those prompts the provider runs as the user and cannot read the protected configuration, so it asks
// this service over a named pipe. See common/broker.h for the protocol and the client checks.
//
//   ZwCredSvc.exe            run as a service (installed by ZwSetup)
//   ZwCredSvc.exe --console  run in the foreground for debugging (as administrator)
#include <windows.h>
#include <sddl.h>
#include <stdio.h>
#include <string>
#include <thread>
#include <atomic>
#include "../common/config.h"
#include "../common/proto.h"
#include "../common/sha256.h"
#include "../common/i18n.h"
#include "../common/broker.h"

using namespace zw;

static SERVICE_STATUS_HANDLE g_ssh = nullptr;
static SERVICE_STATUS g_ss = {};
static HANDLE g_stop = nullptr;
static bool g_console = false;

static void SvcLog(const wchar_t* fmt, const std::wstring& a = L"", const std::wstring& b = L"") {
    std::wstring line = std::wstring(L"[svc] ") + fmt;
    Log(line.c_str(), a.c_str(), b.c_str());
    if (g_console) { wprintf(line.c_str(), a.c_str(), b.c_str()); wprintf(L"\n"); }
}

// ---------- pipe connection with overlapped I/O (reads and writes may run on two threads) ----------
struct Conn {
    HANDLE h;
    std::string rx;
    explicit Conn(HANDLE pipe) : h(pipe) {}
    bool Write(const std::string& line) {
        std::string s = line + "\n";
        OVERLAPPED ov = {}; ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        DWORD n = 0;
        BOOL ok = WriteFile(h, s.data(), (DWORD)s.size(), nullptr, &ov);
        if (!ok && GetLastError() == ERROR_IO_PENDING) ok = GetOverlappedResult(h, &ov, &n, TRUE);
        CloseHandle(ov.hEvent);
        SecureZeroMemory(&s[0], s.size());
        return ok != FALSE;
    }
    // 0 = line, 1 = timeout, -1 = closed
    int ReadLine(std::string& line, DWORD timeoutMs) {
        for (;;) {
            size_t nl = rx.find('\n');
            if (nl != std::string::npos) {
                line = rx.substr(0, nl); rx.erase(0, nl + 1);
                while (!line.empty() && line.back() == '\r') line.pop_back();
                return 0;
            }
            char buf[256]; DWORD got = 0;
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
            if (rx.size() > 4096) return -1;
        }
    }
};

static std::string W2U(const std::wstring& w) {
    if (w.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}

// ---------- client checks ----------
static bool ClientImage(HANDLE pipe, std::wstring& image) {
    ULONG pid = 0;
    if (!GetNamedPipeClientProcessId(pipe, &pid)) return false;
    HANDLE p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!p) return false;
    wchar_t path[MAX_PATH * 2]; DWORD n = MAX_PATH * 2;
    BOOL ok = QueryFullProcessImageNameW(p, 0, path, &n);
    CloseHandle(p);
    if (ok) image.assign(path, n);
    return ok != FALSE;
}

static bool ClientIsCredUiBroker(const std::wstring& image) {
    wchar_t sys[MAX_PATH]; GetSystemDirectoryW(sys, MAX_PATH);
    return _wcsicmp(image.c_str(), (std::wstring(sys) + L"\\CredentialUIBroker.exe").c_str()) == 0;
}

static bool ClientSid(HANDLE pipe, std::wstring& sid) {
    if (!ImpersonateNamedPipeClient(pipe)) return false;
    HANDLE tok = nullptr;
    BOOL ok = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &tok);
    RevertToSelf();
    if (!ok) return false;
    BYTE buf[256]; DWORD n = 0;
    bool res = false;
    if (GetTokenInformation(tok, TokenUser, buf, sizeof(buf), &n)) {
        LPWSTR s = nullptr;
        if (ConvertSidToStringSidW(((TOKEN_USER*)buf)->User.Sid, &s)) { sid = s; LocalFree(s); res = true; }
    }
    CloseHandle(tok);
    return res;
}

// ---------- requests ----------
static void HandleInfo(Conn& c) {
    Config cfg; bool ok = LoadConfig(cfg);
    bool enabled = ok && cfg.enabled && cfg.credUiEnabled;
    char head[64];
    snprintf(head, sizeof(head), "INFO %d %d %s", enabled ? 1 : 0, cfg.debug ? 1 : 0, W2U(cfg.lang.empty() ? L"auto" : cfg.lang).c_str());
    c.Write(head);
    c.Write(W2U(cfg.user));
    c.Write(W2U(EffectiveDomain(cfg)));
    c.Write(W2U(cfg.userSid));
}

static void HandleAuth(Conn& c) {
    Config cfg; std::wstring werr;
    if (!LoadConfig(cfg, &werr)) { c.Write("ERR CONFIG"); return; }
    LogEnable(cfg.debug);
    if (!cfg.enabled || !cfg.credUiEnabled) { c.Write("ERR DISABLED"); return; }

    std::wstring image, sid;
    if (!ClientImage(c.h, image) || !ClientIsCredUiBroker(image)) {
        SvcLog(L"AUTH refused: client image %ls", image);
        c.Write("ERR CLIENT");
        return;
    }
    if (cfg.userSid.empty() || !ClientSid(c.h, sid) || _wcsicmp(sid.c_str(), cfg.userSid.c_str()) != 0) {
        SvcLog(L"AUTH refused: client user %ls, configured %ls", sid, cfg.userSid);
        c.Write("ERR USER");
        return;
    }

    Secrets s;
    if (!UnprotectSecrets(cfg.blob, s, &werr)) { c.Write("ERR KEY"); return; }
    SerialPort port;
    if (!OpenDevice(port, cfg.port, cfg.usbId)) { c.Write("ERR NODEVICE"); return; }

    // Watch the pipe for CANCEL / client gone, and the service for stop, while the device waits for a finger.
    std::atomic<bool> cancel{false}, done{false};
    std::thread watcher([&] {
        std::string l;
        while (!done.load()) {
            if (WaitForSingleObject(g_stop, 0) == WAIT_OBJECT_0) { cancel = true; break; }
            int r = c.ReadLine(l, 250);
            if (r < 0 || (r == 0 && l == "CANCEL")) { cancel = true; break; }
        }
    });

    uint8_t kdev[32]; int fingerId = 0; std::string err;
    AuthResult r = RunAuth(port, s.kauth, cancel, kdev, fingerId, &err,
                           [&](const std::string& ev) { c.Write("EV " + ev); }, 120000);
    done = true;
    watcher.join();

    switch (r) {
    case AuthResult::Match: {
        if (cfg.fingerId != 0 && (DWORD)fingerId != cfg.fingerId) { SecureZeroMemory(kdev, 32); c.Write("ERR FINGER"); return; }
        std::wstring pw;
        bool ok = OpenPassword(s, kdev, pw);
        SecureZeroMemory(kdev, 32);
        if (!ok) { c.Write("ERR KEY"); return; }
        std::string hex = "PW ";
        hex.reserve(3 + pw.size() * 4);
        static const char* d = "0123456789abcdef";
        for (wchar_t ch : pw) {
            unsigned v = (unsigned)ch;
            hex += d[(v >> 4) & 15]; hex += d[v & 15]; hex += d[(v >> 12) & 15]; hex += d[(v >> 8) & 15];
        }
        if (!pw.empty()) SecureZeroMemory(&pw[0], pw.size() * sizeof(wchar_t));
        c.Write(hex);
        SecureZeroMemory(&hex[0], hex.size());
        SvcLog(L"AUTH ok for %ls", cfg.user);
        return;
    }
    case AuthResult::Cancelled: c.Write("ERR CANCELLED"); return;
    case AuthResult::Timeout: c.Write("ERR TIMEOUT"); return;
    case AuthResult::NoDevice: c.Write("ERR NODEVICE"); return;
    case AuthResult::NotProvisioned: c.Write("ERR NOTPROVISIONED"); return;
    case AuthResult::AuthFailed: c.Write("ERR AUTHFAILED"); return;
    default: c.Write("ERR DEVICE " + err); return;
    }
}

static void HandleClient(HANDLE pipe) {
    Conn c(pipe);
    std::string line;
    if (c.ReadLine(line, 5000) != 0) return;
    if (line == "INFO") HandleInfo(c);
    else if (line == "AUTH") HandleAuth(c);
    else c.Write("ERR UNKNOWN");
}

// ---------- server loop ----------
static void ServeLoop() {
    // SYSTEM and administrators: full; interactive users: read/write. Remote clients are rejected.
    PSECURITY_DESCRIPTOR sd = nullptr;
    ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x0012019f;;;IU)", SDDL_REVISION_1, &sd, nullptr);
    SECURITY_ATTRIBUTES sa = { sizeof(sa), sd, FALSE };
    HANDLE pipe = CreateNamedPipeW(kBrokerPipe, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                                   PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                                   1, 4096, 4096, 0, &sa);
    if (sd) LocalFree(sd);
    if (pipe == INVALID_HANDLE_VALUE) { SvcLog(L"CreateNamedPipe failed"); return; }
    HANDLE ev = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    for (;;) {
        OVERLAPPED ov = {}; ov.hEvent = ev; ResetEvent(ev);
        BOOL ok = ConnectNamedPipe(pipe, &ov);
        DWORD e = GetLastError();
        if (!ok && e == ERROR_IO_PENDING) {
            HANDLE w[2] = { ev, g_stop };
            if (WaitForMultipleObjects(2, w, FALSE, INFINITE) != WAIT_OBJECT_0) { CancelIo(pipe); break; }
        } else if (!ok && e != ERROR_PIPE_CONNECTED) { Sleep(200); continue; }
        HandleClient(pipe);
        FlushFileBuffers(pipe);
        DisconnectNamedPipe(pipe);
        if (WaitForSingleObject(g_stop, 0) == WAIT_OBJECT_0) break;
    }
    CloseHandle(ev);
    CloseHandle(pipe);
}

static void Report(DWORD state) {
    g_ss.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ss.dwCurrentState = state;
    g_ss.dwControlsAccepted = state == SERVICE_RUNNING ? (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN) : 0;
    g_ss.dwWaitHint = state == SERVICE_RUNNING || state == SERVICE_STOPPED ? 0 : 5000;
    SetServiceStatus(g_ssh, &g_ss);
}

static DWORD WINAPI Handler(DWORD ctrl, DWORD, LPVOID, LPVOID) {
    if (ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN) { Report(SERVICE_STOP_PENDING); SetEvent(g_stop); return NO_ERROR; }
    return ctrl == SERVICE_CONTROL_INTERROGATE ? NO_ERROR : ERROR_CALL_NOT_IMPLEMENTED;
}

static void WINAPI ServiceMain(DWORD, LPWSTR*) {
    g_ssh = RegisterServiceCtrlHandlerExW(kServiceName, Handler, nullptr);
    if (!g_ssh) return;
    Report(SERVICE_START_PENDING);
    Report(SERVICE_RUNNING);
    { Config cfg; LoadConfig(cfg); LogEnable(cfg.debug); }
    SvcLog(L"started");
    ServeLoop();
    SvcLog(L"stopped");
    Report(SERVICE_STOPPED);
}

int wmain(int argc, wchar_t** argv) {
    g_stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (argc > 1 && _wcsicmp(argv[1], L"--console") == 0) {
        g_console = true;
        LogEnable(true);
        SetConsoleCtrlHandler([](DWORD) -> BOOL { SetEvent(g_stop); return TRUE; }, TRUE);
        wprintf(L"ZwCredSvc in console mode, Ctrl+C to stop. Pipe: %ls\n", kBrokerPipe);
        ServeLoop();
        return 0;
    }
    SERVICE_TABLE_ENTRYW table[] = { { (LPWSTR)kServiceName, ServiceMain }, { nullptr, nullptr } };
    if (!StartServiceCtrlDispatcherW(table)) {
        fwprintf(stderr, L"ZwCredSvc is a Windows service; install and enable it from ZwSetup (Settings).\n");
        return 1;
    }
    return 0;
}
