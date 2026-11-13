// zwsetup-gui: Win32 front-end for ZwCredProv setup. Requires administrator (see manifest).
#include <windows.h>
#include <commctrl.h>
#include <shlwapi.h>
#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include <memory>
#include "resource.h"
#include "../common/config.h"
#include "../common/proto.h"
#include "../common/sha256.h"
#include "../common/i18n.h"

using namespace zw;

#define WM_APP_LOG     (WM_APP + 1)   // lParam: std::wstring* (owned)
#define WM_APP_DONE    (WM_APP + 2)
#define WM_APP_STATUS  (WM_APP + 3)   // lParam: std::wstring* (owned)
static const INT_PTR kRestartDialog = 2;

static HWND g_hwnd = nullptr;
static std::atomic<bool> g_busy{false};
static std::wstring g_langSetting = L"auto";   // current Lang setting ("auto" | "ru" | "en")
static const wchar_t* kCpRegKey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\{7B2F3C1E-9A4D-4E6B-8C21-5D0E9F3A6B47}";

// ---------- helpers callable from the worker thread ----------
static void Post(UINT msg, const std::wstring& s) { PostMessageW(g_hwnd, msg, 0, (LPARAM)new std::wstring(s)); }
static void LogW(const std::wstring& s) { Post(WM_APP_LOG, s); }
static void SetStatusText(const std::wstring& s) { Post(WM_APP_STATUS, s); }
static bool Ask(const std::wstring& text, UINT flags = MB_OKCANCEL | MB_ICONINFORMATION) {
    return MessageBoxW(g_hwnd, text.c_str(), T(S::GUI_TITLE), flags) == IDOK;
}
static void Fail(const std::wstring& text) {
    LogW(Ts(S::GUI_ERROR_PREFIX) + text);
    MessageBoxW(g_hwnd, text.c_str(), T(S::GUI_ERROR_TITLE), MB_OK | MB_ICONERROR);
}
static std::wstring GetText(int id) { wchar_t buf[512]; GetDlgItemTextW(g_hwnd, id, buf, 512); return buf; }
static void Zero(std::wstring& s) { if (!s.empty()) SecureZeroMemory(&s[0], s.size() * sizeof(wchar_t)); s.clear(); }
static std::wstring N(int v) { return std::to_wstring(v); }

struct Form {
    std::wstring user, domain, pass, pass2, port, usbId;
    DWORD finger = 0; int enrollId = 1; bool debug = false;
    ~Form() { Zero(pass); Zero(pass2); }
};
static std::shared_ptr<Form> ReadForm() {
    auto f = std::make_shared<Form>();
    f->user = GetText(IDC_USER); f->domain = GetText(IDC_DOMAIN);
    f->pass = GetText(IDC_PASS); f->pass2 = GetText(IDC_PASS2);
    f->port = GetText(IDC_PORT); f->usbId = GetText(IDC_USBID);
    f->finger = (DWORD)_wtoi(GetText(IDC_FINGER).c_str());
    f->enrollId = _wtoi(GetText(IDC_ENROLL_ID).c_str());
    f->debug = IsDlgButtonChecked(g_hwnd, IDC_DEBUG) == BST_CHECKED;
    if (f->domain.empty()) f->domain = L".";
    if (f->port.empty()) f->port = L"auto";
    return f;
}

static bool DllRegistered() {
    HKEY k;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kCpRegKey, 0, KEY_READ | KEY_WOW64_64KEY, &k) != ERROR_SUCCESS) return false;
    RegCloseKey(k); return true;
}
static std::wstring System32Dll() { wchar_t dir[MAX_PATH]; GetSystemDirectoryW(dir, MAX_PATH); return std::wstring(dir) + L"\\ZwCredProv.dll"; }
static std::wstring LocalDll() { wchar_t path[MAX_PATH]; GetModuleFileNameW(nullptr, path, MAX_PATH); PathRemoveFileSpecW(path); return std::wstring(path) + L"\\ZwCredProv.dll"; }

static bool OpenDev(SerialPort& port, const Form& f, const Config& cfg) {
    std::wstring chosen, diag;
    std::wstring p = f.port.empty() ? cfg.port : f.port;
    std::wstring u = f.usbId.empty() ? cfg.usbId : f.usbId;
    if (!OpenDevice(port, p, u, &chosen, &diag)) {
        wchar_t msg[512]; _snwprintf(msg, 512, T(S::DEVICE_NOT_FOUND), p.c_str(), u.c_str());
        Fail(std::wstring(msg) + L"\n" + diag);
        return false;
    }
    LogW(Ts(S::DEVICE_FOUND_ON) + chosen);
    return true;
}

static bool AuthGetKdev(SerialPort& port, const Secrets& s, uint8_t kdev[32]) {
    std::atomic<bool> cancel{false}; int id = 0; std::string err;
    AuthResult r = RunAuth(port, s.kauth, cancel, kdev, id, &err, [](const std::string& ev) {
        if (ev == "WAIT") LogW(T(S::PLACE_FINGER));
        else if (ev == "NOMATCH") LogW(T(S::NOMATCH_RETRY));
        else if (ev == "READY") LogW(T(S::PLACE_FINGER));
        else if (ev.compare(0, 7, "LOCKED ") == 0) { wchar_t m[200]; _snwprintf(m, 200, T(S::LOCKED_FMT), (unsigned)atoi(ev.c_str() + 7)); LogW(m); }
    }, 60000);
    switch (r) {
    case AuthResult::Match: LogW(Ts(S::MATCH_ID) + N(id)); return true;
    case AuthResult::NoDevice: Fail(Ts(S::ERR_COMM) + A2W(err)); break;
    case AuthResult::NotProvisioned: Fail(T(S::ERR_NOT_PROVISIONED)); break;
    case AuthResult::AuthFailed: Fail(T(S::ERR_AUTH_FAILED)); break;
    case AuthResult::Timeout: Fail(T(S::ERR_TIMEOUT)); break;
    case AuthResult::Cancelled: break;
    case AuthResult::Error: Fail(Ts(S::ERR_PROTOCOL) + A2W(err)); break;
    }
    return false;
}

// ---------- operations (worker thread) ----------
static void OpStatus() {
    Config cfg; std::wstring err; std::wstring st;
    bool ok = LoadConfig(cfg, &err);
    st += ok ? Ts(S::GUI_ST_CFG_USER) + EffectiveDomain(cfg) + L"\\" + cfg.user + T(cfg.enabled ? S::GUI_ST_TILE_ON : S::GUI_ST_TILE_OFF)
             : Ts(S::GUI_ST_NOT_CFG);
    st += T(DllRegistered() ? S::GUI_ST_DLL_REG : S::GUI_ST_DLL_NOT_REG);
    auto all = ListComPorts();
    LogW(T(all.empty() ? S::GUI_PORTS_NONE : S::GUI_PORTS));
    for (auto& p : all) LogW(L"  " + p.first + L"  " + p.second);
    std::wstring usb = GetText(IDC_USBID); if (usb.empty()) usb = cfg.usbId;
    std::wstring portSetting = GetText(IDC_PORT); if (portSetting.empty()) portSetting = cfg.port;
    SerialPort dev; std::wstring chosen, diag;
    if (OpenDevice(dev, portSetting, usb, &chosen, &diag)) {
        DeviceInfo info; Hello(dev, info);
        st += Ts(S::GUI_ST_DEVICE_ON) + chosen + T(S::GUI_ST_KEYS) + T(info.provisioned ? S::GUI_ST_KEYS_YES : S::GUI_ST_KEYS_NO) + T(S::GUI_ST_TEMPLATES) + N(info.templates);
    } else st += Ts(S::GUI_ST_NO_DEVICE) + diag;
    SetStatusText(st);
}

static void OpProvision(std::shared_ptr<Form> f) {
    if (f->user.empty()) { Fail(T(S::ERR_USER_EMPTY)); return; }
    if (f->pass != f->pass2) { Fail(T(S::ERR_PW_MISMATCH)); return; }
    if (f->pass.empty() && !Ask(T(S::PW_EMPTY_Q), MB_OKCANCEL | MB_ICONWARNING)) return;
    Config cfg; LoadConfig(cfg);
    cfg.user = f->user; cfg.domain = f->domain; cfg.port = f->port; cfg.usbId = f->usbId;
    cfg.fingerId = f->finger; cfg.debug = f->debug; cfg.enabled = true; cfg.lang = g_langSetting;

    std::wstring email;
    if (cfg.domain == L"." && LinkedMicrosoftAccount(cfg.user, email)) {
        if (Ask(Ts(S::MSA_LINKED_A) + cfg.user + T(S::MSA_LINKED_B) + email + T(S::MSA_OFFER_A) + email + T(S::MSA_OFFER_B))) {
            cfg.domain = L"MicrosoftAccount"; cfg.user = email;
            LogW(Ts(S::MSA_USING) + email);
        }
    }
    if (_wcsicmp(cfg.domain.c_str(), L"MicrosoftAccount") == 0 && cfg.user.find(L'@') == std::wstring::npos) {
        if (!Ask(Ts(S::MSA_NEEDS_EMAIL) + T(S::CONTINUE_ANYWAY), MB_OKCANCEL | MB_ICONWARNING)) return;
    }
    std::wstring qualified = EffectiveDomain(cfg) + L"\\" + cfg.user;
    BYTE sid[SECURITY_MAX_SID_SIZE]; DWORD cb = sizeof(sid); wchar_t dom[256]; DWORD cd = 256; SID_NAME_USE use;
    if (!LookupAccountNameW(nullptr, qualified.c_str(), sid, &cb, dom, &cd, &use)) {
        wchar_t msg[512]; _snwprintf(msg, 512, T(S::ACCOUNT_NOT_FOUND), qualified.c_str());
        if (!Ask(std::wstring(msg) + T(S::ACCOUNT_MSA_HINT) + T(S::CONTINUE_ANYWAY), MB_OKCANCEL | MB_ICONWARNING)) return;
    } else LogW(Ts(S::ACCOUNT_IS) + qualified);

    SerialPort dev;
    if (!OpenDev(dev, *f, cfg)) return;

    Secrets s; uint8_t kdev[32];
    if (!RandomBytes(kdev, 32) || !RandomBytes(s.kpc, 32) || !RandomBytes(s.kauth, 32)) { Fail(T(S::ERR_RNG)); return; }
    if (!Ask(T(S::HOLD_BUTTON))) { SecureZeroMemory(kdev, 32); return; }
    std::string err;
    if (!Provision(dev, kdev, s.kauth, &err)) {
        SecureZeroMemory(kdev, 32);
        Fail(Ts(S::DEVICE_REFUSED) + A2W(err) + T(S::BUTTON_HELD_Q));
        return;
    }
    LogW(T(S::KEYS_WRITTEN));
    bool sealed = SealPassword(s, kdev, f->pass);
    SecureZeroMemory(kdev, 32);
    if (!sealed) { Fail(T(S::ERR_ENCRYPT)); return; }
    std::wstring werr;
    if (!ProtectSecrets(s, cfg.blob, &werr) || !SaveConfig(cfg, &werr)) { Fail(Ts(S::ERR_SAVE_CFG) + werr); return; }
    LogW(T(S::CFG_SAVED));
    DeviceInfo info; Hello(dev, info);
    if (info.templates == 0) LogW(T(S::NO_TEMPLATES));
    else LogW(Ts(S::TEMPLATES_N) + N(info.templates) + T(S::GO_STEP3));
    if (!DllRegistered()) LogW(T(S::DLL_NOT_REG_HINT));
}

static void OpEnroll(std::shared_ptr<Form> f, bool del) {
    if (f->enrollId <= 0 || f->enrollId > 199) { Fail(T(S::ERR_SLOT_RANGE)); return; }
    Config cfg; LoadConfig(cfg);
    SerialPort dev;
    if (!OpenDev(dev, *f, cfg)) return;
    if (!Ask(T(S::HOLD_BUTTON))) return;
    std::string err;
    if (del) {
        if (!DeleteFinger(dev, f->enrollId, &err)) { Fail(Ts(S::DELETE_ERR) + A2W(err)); return; }
        LogW(Ts(S::SLOT_DELETED_A) + N(f->enrollId) + T(S::SLOT_DELETED_B)); return;
    }
    bool ok = Enroll(dev, f->enrollId, [](const std::string& ev) {
        if (ev == "PLACE") LogW(T(S::ENROLL_PLACE));
        else if (ev == "REMOVE") LogW(T(S::ENROLL_REMOVE));
        else if (ev == "AGAIN") LogW(T(S::ENROLL_AGAIN));
    }, &err);
    if (!ok) { Fail(Ts(S::ENROLL_ERR) + A2W(err)); return; }
    LogW(Ts(S::ENROLLED_SLOT) + N(f->enrollId) + L".");
}

static void OpTest(std::shared_ptr<Form> f) {
    Config cfg; std::wstring werr;
    if (!LoadConfig(cfg, &werr)) { Fail(werr); return; }
    Secrets s;
    if (!UnprotectSecrets(cfg.blob, s, &werr)) { Fail(Ts(S::ERR_UNPROTECT) + werr); return; }
    SerialPort dev;
    if (!OpenDev(dev, *f, cfg)) return;
    uint8_t kdev[32];
    if (!AuthGetKdev(dev, s, kdev)) return;
    std::wstring pw;
    bool ok = OpenPassword(s, kdev, pw);
    SecureZeroMemory(kdev, 32);
    if (!ok) { Fail(T(S::PW_NOT_DECRYPTED)); return; }
    LogW(T(S::PW_DECRYPTED));
    HANDLE tok = nullptr;
    std::wstring dom = EffectiveDomain(cfg);
    if (LogonUserW(cfg.user.c_str(), dom.c_str(), pw.c_str(), LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &tok)) {
        CloseHandle(tok);
        LogW(T(S::LOGON_OK));
        if (!DllRegistered()) LogW(T(S::DLL_NOT_REG_HINT));
    } else {
        DWORD e = GetLastError();
        LogW(Ts(S::LOGON_FAIL_A) + N((int)e) + T(S::LOGON_FAIL_B));
        std::wstring email;
        if (cfg.domain == L"." && LinkedMicrosoftAccount(cfg.user, email))
            LogW(Ts(S::MSA_LINKED_A) + cfg.user + T(S::MSA_LINKED_B) + email + T(S::MSA_LINKED_FIX) + email + T(S::MSA_LINKED_FIX2));
        else LogW(T(S::PW_HINT));
    }
    Zero(pw);
}

static void OpSetPassword(std::shared_ptr<Form> f) {
    if (f->pass != f->pass2) { Fail(T(S::ERR_PW_MISMATCH)); return; }
    Config cfg; std::wstring werr;
    if (!LoadConfig(cfg, &werr)) { Fail(werr); return; }
    Secrets s;
    if (!UnprotectSecrets(cfg.blob, s, &werr)) { Fail(Ts(S::ERR_UNPROTECT) + werr); return; }
    SerialPort dev;
    if (!OpenDev(dev, *f, cfg)) return;
    uint8_t kdev[32];
    if (!AuthGetKdev(dev, s, kdev)) return;
    bool ok = SealPassword(s, kdev, f->pass);
    SecureZeroMemory(kdev, 32);
    if (!ok || !ProtectSecrets(s, cfg.blob, &werr) || !SaveConfig(cfg, &werr)) { Fail(Ts(S::ERR_SAVE_CFG) + werr); return; }
    LogW(T(S::PW_UPDATED));
}

static void OpToggle() {
    Config cfg; std::wstring werr;
    if (!LoadConfig(cfg, &werr)) { Fail(werr); return; }
    cfg.enabled = !cfg.enabled;
    if (!SaveConfig(cfg, &werr)) { Fail(werr); return; }
    LogW(T(cfg.enabled ? S::TILE_ON : S::TILE_OFF));
}

static void OpWipe(std::shared_ptr<Form> f) {
    Config cfg; LoadConfig(cfg);
    SerialPort dev;
    if (!OpenDev(dev, *f, cfg)) return;
    if (!Ask(T(S::WIPE_CONFIRM), MB_OKCANCEL | MB_ICONWARNING)) return;
    std::string err;
    if (!Wipe(dev, &err)) { Fail(Ts(S::ERR_PROTOCOL) + A2W(err)); return; }
    LogW(T(S::WIPED));
}

static void OpUninstall() {
    if (!Ask(T(S::UNINSTALL_CONFIRM), MB_OKCANCEL | MB_ICONWARNING)) return;
    LogW(T(DeleteConfig() ? S::CFG_DELETED : S::NOTHING_TO_DELETE));
    if (DllRegistered()) LogW(T(S::DLL_STILL_REG));
}

typedef HRESULT (WINAPI *RegFn)();
static void OpRegister(bool reg) {
    std::wstring sys = System32Dll(), local = LocalDll();
    if (reg) {
        if (!PathFileExistsW(local.c_str())) { Fail(Ts(S::DLL_MISSING) + local); return; }
        if (!CopyFileW(local.c_str(), sys.c_str(), FALSE)) {
            DWORD e = GetLastError();
            if (e == ERROR_SHARING_VIOLATION || e == ERROR_ACCESS_DENIED) {
                std::wstring tmp = sys + L".new";
                if (CopyFileW(local.c_str(), tmp.c_str(), FALSE) && MoveFileExW(tmp.c_str(), sys.c_str(), MOVEFILE_DELAY_UNTIL_REBOOT | MOVEFILE_REPLACE_EXISTING))
                    LogW(T(S::DLL_BUSY_REBOOT));
                else { Fail(Ts(S::DLL_COPY_FAIL) + N((int)e)); return; }
            } else { Fail(Ts(S::DLL_COPY_FAIL) + N((int)e)); return; }
        } else LogW(Ts(S::DLL_COPIED) + sys);
    }
    HMODULE h = LoadLibraryW(sys.c_str());
    if (!h) { Fail(Ts(S::DLL_LOAD_FAIL) + sys + T(S::ERROR_SUFFIX) + N((int)GetLastError())); return; }
    RegFn fn = (RegFn)GetProcAddress(h, reg ? "DllRegisterServer" : "DllUnregisterServer");
    HRESULT hr = fn ? fn() : E_FAIL;
    FreeLibrary(h);
    if (FAILED(hr)) { wchar_t hx[16]; _snwprintf(hx, 16, L"%08X", (unsigned)hr); Fail(Ts(S::DLL_REG_HR) + hx); return; }
    if (reg) LogW(T(S::DLL_REGISTERED));
    else {
        LogW(T(S::DLL_UNREGISTERED));
        if (!DeleteFileW(sys.c_str())) MoveFileExW(sys.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
    }
}

// ---------- UI plumbing ----------
static const int kButtons[] = { IDC_BTN_STATUS, IDC_BTN_PROVISION, IDC_BTN_ENROLL, IDC_BTN_DELETE, IDC_BTN_TEST, IDC_BTN_SETPW,
                                IDC_BTN_REGISTER, IDC_BTN_UNREGISTER, IDC_BTN_TOGGLE, IDC_BTN_WIPE, IDC_BTN_UNINSTALL, IDC_LANG };
static void EnableButtons(bool on) { for (int id : kButtons) EnableWindow(GetDlgItem(g_hwnd, id), on); }

static void RunOp(std::function<void()> op) {
    if (g_busy.exchange(true)) return;
    EnableButtons(false);
    std::thread([op] { op(); PostMessageW(g_hwnd, WM_APP_DONE, 0, 0); }).detach();
}

static void AppendLog(const std::wstring& s) {
    HWND h = GetDlgItem(g_hwnd, IDC_LOG);
    int len = GetWindowTextLengthW(h);
    SendMessageW(h, EM_SETSEL, len, len);
    std::wstring line = s + L"\r\n";
    SendMessageW(h, EM_REPLACESEL, FALSE, (LPARAM)line.c_str());
}

static void LoadFormFromConfig() {
    Config cfg;
    bool ok = LoadConfig(cfg);
    if (ok) {
        SetDlgItemTextW(g_hwnd, IDC_USER, cfg.user.c_str());
        SetDlgItemTextW(g_hwnd, IDC_DOMAIN, cfg.domain.c_str());
        SetDlgItemInt(g_hwnd, IDC_FINGER, cfg.fingerId, FALSE);
        CheckDlgButton(g_hwnd, IDC_DEBUG, cfg.debug ? BST_CHECKED : BST_UNCHECKED);
    } else {
        wchar_t name[256]; DWORD n = 256; std::wstring email;
        if (GetUserNameW(name, &n)) {
            if (LinkedMicrosoftAccount(name, email)) { SetDlgItemTextW(g_hwnd, IDC_USER, email.c_str()); SetDlgItemTextW(g_hwnd, IDC_DOMAIN, L"MicrosoftAccount"); }
            else { SetDlgItemTextW(g_hwnd, IDC_USER, name); SetDlgItemTextW(g_hwnd, IDC_DOMAIN, L"."); }
        } else SetDlgItemTextW(g_hwnd, IDC_DOMAIN, L".");
        SetDlgItemInt(g_hwnd, IDC_FINGER, 0, FALSE);
    }
    SetDlgItemTextW(g_hwnd, IDC_PORT, cfg.port.c_str());
    SetDlgItemTextW(g_hwnd, IDC_USBID, cfg.usbId.c_str());
    SetDlgItemInt(g_hwnd, IDC_ENROLL_ID, 1, FALSE);
    HWND cb = GetDlgItem(g_hwnd, IDC_LANG);
    SendMessageW(cb, CB_ADDSTRING, 0, (LPARAM)(CurrentLang() == Lang::Ru ? L"Авто (как в Windows)" : L"Auto (follow Windows)"));
    SendMessageW(cb, CB_ADDSTRING, 0, (LPARAM)L"Русский");
    SendMessageW(cb, CB_ADDSTRING, 0, (LPARAM)L"English");
    int sel = _wcsicmp(g_langSetting.c_str(), L"ru") == 0 ? 1 : _wcsicmp(g_langSetting.c_str(), L"en") == 0 ? 2 : 0;
    SendMessageW(cb, CB_SETCURSEL, sel, 0);
}

static void OnLangChanged() {
    int sel = (int)SendDlgItemMessageW(g_hwnd, IDC_LANG, CB_GETCURSEL, 0, 0);
    std::wstring setting = sel == 1 ? L"ru" : sel == 2 ? L"en" : L"auto";
    if (setting == g_langSetting) return;
    g_langSetting = setting;
    Config cfg; std::wstring err;
    if (LoadConfig(cfg, &err)) { cfg.lang = setting; SaveConfig(cfg); }   // also changes the tile language
    SetLangFromSetting(setting);
    EndDialog(g_hwnd, kRestartDialog);
}

static INT_PTR CALLBACK DlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_INITDIALOG:
        g_hwnd = hwnd;
        LoadFormFromConfig();
        AppendLog(T(S::GUI_INTRO));
        if (GetText(IDC_DOMAIN) == L"MicrosoftAccount") AppendLog(T(S::GUI_MSA_DETECTED));
        RunOp(OpStatus);
        return TRUE;
    case WM_APP_LOG: { std::unique_ptr<std::wstring> s((std::wstring*)lParam); AppendLog(*s); return TRUE; }
    case WM_APP_STATUS: { std::unique_ptr<std::wstring> s((std::wstring*)lParam); SetDlgItemTextW(hwnd, IDC_STATUS, s->c_str()); return TRUE; }
    case WM_APP_DONE: g_busy = false; EnableButtons(true); return TRUE;
    case WM_COMMAND: {
        int id = LOWORD(wParam);
        if (id == IDC_LANG && HIWORD(wParam) == CBN_SELCHANGE) { OnLangChanged(); return TRUE; }
        if (HIWORD(wParam) != BN_CLICKED && id != IDCANCEL) return FALSE;
        switch (id) {
        case IDCANCEL: EndDialog(hwnd, 0); return TRUE;
        case IDC_BTN_STATUS:    RunOp(OpStatus); return TRUE;
        case IDC_BTN_PROVISION: { auto f = ReadForm(); RunOp([f] { OpProvision(f); OpStatus(); }); return TRUE; }
        case IDC_BTN_ENROLL:    { auto f = ReadForm(); RunOp([f] { OpEnroll(f, false); OpStatus(); }); return TRUE; }
        case IDC_BTN_DELETE:    { auto f = ReadForm(); RunOp([f] { OpEnroll(f, true); OpStatus(); }); return TRUE; }
        case IDC_BTN_TEST:      { auto f = ReadForm(); RunOp([f] { OpTest(f); }); return TRUE; }
        case IDC_BTN_SETPW:     { auto f = ReadForm(); RunOp([f] { OpSetPassword(f); }); return TRUE; }
        case IDC_BTN_REGISTER:  RunOp([] { OpRegister(true); OpStatus(); }); return TRUE;
        case IDC_BTN_UNREGISTER:RunOp([] { OpRegister(false); OpStatus(); }); return TRUE;
        case IDC_BTN_TOGGLE:    RunOp([] { OpToggle(); OpStatus(); }); return TRUE;
        case IDC_BTN_WIPE:      { auto f = ReadForm(); RunOp([f] { OpWipe(f); OpStatus(); }); return TRUE; }
        case IDC_BTN_UNINSTALL: RunOp([] { OpUninstall(); OpStatus(); }); return TRUE;
        }
        return FALSE;
    }
    case WM_CLOSE: EndDialog(hwnd, 0); return TRUE;
    }
    return FALSE;
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int) {
    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icc);
    { Config cfg; LoadConfig(cfg); g_langSetting = cfg.lang; }   // LoadConfig applies Lang
    SetLangFromSetting(g_langSetting);
    INT_PTR r;
    do {
        r = DialogBoxParamW(hInst, MAKEINTRESOURCEW(CurrentLang() == Lang::Ru ? IDD_MAIN_RU : IDD_MAIN_EN), nullptr, DlgProc, 0);
    } while (r == kRestartDialog);
    return 0;
}
