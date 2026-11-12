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

using namespace zw;

#define WM_APP_LOG     (WM_APP + 1)   // lParam: std::wstring* (owned)
#define WM_APP_DONE    (WM_APP + 2)
#define WM_APP_STATUS  (WM_APP + 3)   // lParam: std::wstring* (owned)

static HWND g_hwnd = nullptr;
static std::atomic<bool> g_busy{false};
static const wchar_t* kCpRegKey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\{7B2F3C1E-9A4D-4E6B-8C21-5D0E9F3A6B47}";

// ---------- helpers callable from the worker thread ----------
static void Post(UINT msg, const std::wstring& s) { PostMessageW(g_hwnd, msg, 0, (LPARAM)new std::wstring(s)); }
static void LogW(const std::wstring& s) { Post(WM_APP_LOG, s); }
static void SetStatusText(const std::wstring& s) { Post(WM_APP_STATUS, s); }
// Modal question shown from the worker thread; the main window is its owner.
static bool Ask(const std::wstring& text, UINT flags = MB_OKCANCEL | MB_ICONINFORMATION) {
    return MessageBoxW(g_hwnd, text.c_str(), L"Настройка входа по отпечатку", flags) == IDOK;
}
static void Fail(const std::wstring& text) {
    LogW(L"ОШИБКА: " + text);
    MessageBoxW(g_hwnd, text.c_str(), L"Ошибка", MB_OK | MB_ICONERROR);
}

static std::wstring GetText(int id) {
    wchar_t buf[512]; GetDlgItemTextW(g_hwnd, id, buf, 512); return buf;
}
static void Zero(std::wstring& s) { if (!s.empty()) SecureZeroMemory(&s[0], s.size() * sizeof(wchar_t)); s.clear(); }

// Form values captured on the UI thread before an operation starts.
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
static std::wstring System32Dll() {
    wchar_t dir[MAX_PATH]; GetSystemDirectoryW(dir, MAX_PATH);
    return std::wstring(dir) + L"\\ZwCredProv.dll";
}
static std::wstring LocalDll() {
    wchar_t path[MAX_PATH]; GetModuleFileNameW(nullptr, path, MAX_PATH);
    PathRemoveFileSpecW(path);
    return std::wstring(path) + L"\\ZwCredProv.dll";
}

static bool OpenDev(SerialPort& port, const Form& f, const Config& cfg) {
    std::wstring chosen, diag;
    std::wstring p = f.port.empty() ? cfg.port : f.port;
    std::wstring u = f.usbId.empty() ? cfg.usbId : f.usbId;
    if (!OpenDevice(port, p, u, &chosen, &diag)) {
        Fail(L"Устройство не найдено (порт " + p + L", USB id " + u + L").\n" + diag);
        return false;
    }
    LogW(L"Устройство найдено на " + chosen);
    return true;
}

static bool AuthGetKdev(SerialPort& port, const Secrets& s, uint8_t kdev[32]) {
    std::atomic<bool> cancel{false}; int id = 0; std::string err;
    AuthResult r = RunAuth(port, s.kauth, cancel, kdev, id, &err, [](const std::string& ev) {
        if (ev == "WAIT") LogW(L"Приложите палец к сканеру...");
        else if (ev == "NOMATCH") LogW(L"Палец не распознан, попробуйте ещё раз.");
    });
    switch (r) {
    case AuthResult::Match: LogW(L"Совпадение: палец #" + std::to_wstring(id)); return true;
    case AuthResult::NoDevice: Fail(L"Ошибка связи с устройством: " + A2W(err)); break;
    case AuthResult::NotProvisioned: Fail(L"Устройство не настроено: выполните шаг 1."); break;
    case AuthResult::AuthFailed: Fail(L"Устройство отклонило ключ. Устройство и ПК настроены разными ключами: повторите шаг 1."); break;
    case AuthResult::Timeout: Fail(L"Палец не приложен вовремя."); break;
    case AuthResult::Cancelled: break;
    case AuthResult::Error: Fail(L"Ошибка протокола: " + A2W(err)); break;
    }
    return false;
}

// ---------- operations (run on the worker thread) ----------
static void OpStatus() {
    Config cfg; std::wstring err; std::wstring st;
    bool ok = LoadConfig(cfg, &err);
    st += ok ? L"Конфигурация: пользователь " + EffectiveDomain(cfg) + L"\\" + cfg.user + (cfg.enabled ? L", плитка включена" : L", плитка ВЫКЛЮЧЕНА")
             : L"Конфигурация: не настроено";
    st += DllRegistered() ? L".  DLL зарегистрирована." : L".  DLL НЕ зарегистрирована.";
    auto all = ListComPorts();
    LogW(all.empty() ? L"COM-портов нет." : L"COM-порты:");
    for (auto& p : all) LogW(L"  " + p.first + L"  " + p.second);
    std::wstring usb = GetText(IDC_USBID); if (usb.empty()) usb = cfg.usbId;
    std::wstring portSetting = GetText(IDC_PORT); if (portSetting.empty()) portSetting = cfg.port;
    SerialPort dev; std::wstring chosen, diag;
    if (OpenDevice(dev, portSetting, usb, &chosen, &diag)) {
        DeviceInfo info; Hello(dev, info);
        st += L"\nУстройство на " + chosen + L": ключи " + (info.provisioned ? L"записаны" : L"НЕ записаны") + L", отпечатков в сканере: " + std::to_wstring(info.templates);
    } else {
        st += L"\nУстройство не найдено. " + diag;
    }
    SetStatusText(st);
}

static void OpProvision(std::shared_ptr<Form> f) {
    if (f->user.empty()) { Fail(L"Укажите имя пользователя."); return; }
    if (f->pass != f->pass2) { Fail(L"Пароли не совпадают."); return; }
    if (f->pass.empty() && !Ask(L"Пароль пустой. Продолжить?", MB_OKCANCEL | MB_ICONWARNING)) return;
    Config cfg; LoadConfig(cfg);
    cfg.user = f->user; cfg.domain = f->domain; cfg.port = f->port; cfg.usbId = f->usbId;
    cfg.fingerId = f->finger; cfg.debug = f->debug; cfg.enabled = true;

    std::wstring qualified = EffectiveDomain(cfg) + L"\\" + cfg.user;
    BYTE sid[SECURITY_MAX_SID_SIZE]; DWORD cb = sizeof(sid); wchar_t dom[256]; DWORD cd = 256; SID_NAME_USE use;
    if (!LookupAccountNameW(nullptr, qualified.c_str(), sid, &cb, dom, &cd, &use)) {
        if (!Ask(L"Учётная запись " + qualified + L" не найдена.\nДля аккаунта Microsoft укажите домен MicrosoftAccount и почту как имя.\nПродолжить всё равно?", MB_OKCANCEL | MB_ICONWARNING)) return;
    } else LogW(L"Учётная запись: " + qualified);
    if (_wcsicmp(cfg.domain.c_str(), L"MicrosoftAccount") == 0 && cfg.user.find(L'@') == std::wstring::npos) {
        if (!Ask(L"Для домена MicrosoftAccount имя пользователя должно быть почтой аккаунта (name@outlook.com).\nПродолжить всё равно?", MB_OKCANCEL | MB_ICONWARNING)) return;
    }

    SerialPort dev;
    if (!OpenDev(dev, *f, cfg)) return;

    Secrets s; uint8_t kdev[32];
    if (!RandomBytes(kdev, 32) || !RandomBytes(s.kpc, 32) || !RandomBytes(s.kauth, 32)) { Fail(L"Ошибка генератора случайных чисел"); return; }
    if (!Ask(L"Зажмите и держите кнопку USR (или BOOT) на плате, затем нажмите OK.")) { SecureZeroMemory(kdev, 32); return; }
    std::string err;
    if (!Provision(dev, kdev, s.kauth, &err)) {
        SecureZeroMemory(kdev, 32);
        Fail(L"Устройство отказало: " + A2W(err) + L"\nКнопка была зажата в момент нажатия OK?");
        return;
    }
    LogW(L"Ключи записаны в устройство. Кнопку можно отпустить.");
    bool sealed = SealPassword(s, kdev, f->pass);
    SecureZeroMemory(kdev, 32);
    if (!sealed) { Fail(L"Ошибка шифрования пароля"); return; }
    std::wstring werr;
    if (!ProtectSecrets(s, cfg.blob, &werr) || !SaveConfig(cfg, &werr)) { Fail(L"Ошибка записи конфигурации: " + werr); return; }
    LogW(L"Конфигурация сохранена в реестре (доступ только SYSTEM и администраторам).");
    DeviceInfo info; Hello(dev, info);
    if (info.templates == 0) LogW(L"В сканере нет отпечатков: выполните шаг 2.");
    else LogW(L"В сканере отпечатков: " + std::to_wstring(info.templates) + L". Можно переходить к шагу 3.");
    if (!DllRegistered()) LogW(L"DLL ещё не зарегистрирована: нажмите «Зарегистрировать DLL».");
}

static void OpEnroll(std::shared_ptr<Form> f, bool del) {
    if (f->enrollId <= 0 || f->enrollId > 199) { Fail(L"Укажите слот пальца от 1 до 199."); return; }
    Config cfg; LoadConfig(cfg);
    SerialPort dev;
    if (!OpenDev(dev, *f, cfg)) return;
    if (!Ask(L"Зажмите и держите кнопку USR (или BOOT) на плате, затем нажмите OK.")) return;
    std::string err;
    if (del) {
        if (!DeleteFinger(dev, f->enrollId, &err)) { Fail(L"Ошибка удаления: " + A2W(err)); return; }
        LogW(L"Слот " + std::to_wstring(f->enrollId) + L" удалён."); return;
    }
    bool ok = Enroll(dev, f->enrollId, [](const std::string& ev) {
        if (ev == "PLACE") LogW(L"Приложите палец (кнопку можно отпустить)...");
        else if (ev == "REMOVE") LogW(L"Уберите палец...");
        else if (ev == "AGAIN") LogW(L"Приложите тот же палец ещё раз...");
    }, &err);
    if (!ok) { Fail(L"Ошибка записи пальца: " + A2W(err)); return; }
    LogW(L"Палец записан в слот " + std::to_wstring(f->enrollId) + L".");
}

static void OpTest(std::shared_ptr<Form> f) {
    Config cfg; std::wstring werr;
    if (!LoadConfig(cfg, &werr)) { Fail(werr); return; }
    Secrets s;
    if (!UnprotectSecrets(cfg.blob, s, &werr)) { Fail(L"Не удалось расшифровать конфигурацию: " + werr); return; }
    SerialPort dev;
    if (!OpenDev(dev, *f, cfg)) return;
    uint8_t kdev[32];
    if (!AuthGetKdev(dev, s, kdev)) return;
    std::wstring pw;
    bool ok = OpenPassword(s, kdev, pw);
    SecureZeroMemory(kdev, 32);
    if (!ok) { Fail(L"Пароль не расшифрован: ключи устройства и ПК не совпадают. Повторите шаг 1."); return; }
    LogW(L"Пароль расшифрован. Проверяю через LogonUser...");
    HANDLE tok = nullptr;
    std::wstring dom = EffectiveDomain(cfg);
    if (LogonUserW(cfg.user.c_str(), dom.c_str(), pw.c_str(), LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &tok)) {
        CloseHandle(tok);
        LogW(L"LogonUser: OK. Всё готово: нажмите Win+L и приложите палец.");
        if (!DllRegistered()) LogW(L"Но DLL не зарегистрирована: нажмите «Зарегистрировать DLL».");
    } else {
        DWORD e = GetLastError();
        LogW(L"LogonUser не удался, ошибка " + std::to_wstring(e) + L". Для локальной учётной записи это неверный пароль (используйте «Сменить пароль»); для аккаунта Microsoft проверьте на экране блокировки.");
    }
    Zero(pw);
}

static void OpSetPassword(std::shared_ptr<Form> f) {
    if (f->pass != f->pass2) { Fail(L"Пароли не совпадают."); return; }
    Config cfg; std::wstring werr;
    if (!LoadConfig(cfg, &werr)) { Fail(werr); return; }
    Secrets s;
    if (!UnprotectSecrets(cfg.blob, s, &werr)) { Fail(L"Не удалось расшифровать конфигурацию: " + werr); return; }
    SerialPort dev;
    if (!OpenDev(dev, *f, cfg)) return;
    uint8_t kdev[32];
    if (!AuthGetKdev(dev, s, kdev)) return;
    bool ok = SealPassword(s, kdev, f->pass);
    SecureZeroMemory(kdev, 32);
    if (!ok || !ProtectSecrets(s, cfg.blob, &werr) || !SaveConfig(cfg, &werr)) { Fail(L"Ошибка: " + werr); return; }
    LogW(L"Пароль обновлён.");
}

static void OpToggle() {
    Config cfg; std::wstring werr;
    if (!LoadConfig(cfg, &werr)) { Fail(werr); return; }
    cfg.enabled = !cfg.enabled;
    if (!SaveConfig(cfg, &werr)) { Fail(werr); return; }
    LogW(cfg.enabled ? L"Плитка включена." : L"Плитка выключена (настройки сохранены).");
}

static void OpWipe(std::shared_ptr<Form> f) {
    Config cfg; LoadConfig(cfg);
    SerialPort dev;
    if (!OpenDev(dev, *f, cfg)) return;
    if (!Ask(L"Будут стёрты ключи и ВСЕ отпечатки в устройстве.\nЗажмите USR (или BOOT) и нажмите OK.", MB_OKCANCEL | MB_ICONWARNING)) return;
    std::string err;
    if (!Wipe(dev, &err)) { Fail(L"Ошибка: " + A2W(err)); return; }
    LogW(L"Устройство очищено.");
}

static void OpUninstall() {
    if (!Ask(L"Удалить конфигурацию из реестра? Устройство не трогается.", MB_OKCANCEL | MB_ICONWARNING)) return;
    LogW(DeleteConfig() ? L"Конфигурация удалена." : L"Нечего удалять.");
    if (DllRegistered()) LogW(L"DLL всё ещё зарегистрирована: при необходимости нажмите «Снять регистрацию DLL».");
}

typedef HRESULT (WINAPI *RegFn)();
static void OpRegister(bool reg) {
    std::wstring sys = System32Dll(), local = LocalDll();
    if (reg) {
        if (!PathFileExistsW(local.c_str())) { Fail(L"Рядом с программой нет ZwCredProv.dll:\n" + local); return; }
        if (!CopyFileW(local.c_str(), sys.c_str(), FALSE)) {
            DWORD e = GetLastError();
            if (e == ERROR_SHARING_VIOLATION || e == ERROR_ACCESS_DENIED) {
                // The old copy may be loaded by LogonUI: schedule replacement after reboot.
                std::wstring tmp = sys + L".new";
                if (CopyFileW(local.c_str(), tmp.c_str(), FALSE) && MoveFileExW(tmp.c_str(), sys.c_str(), MOVEFILE_DELAY_UNTIL_REBOOT | MOVEFILE_REPLACE_EXISTING))
                    LogW(L"Старая DLL занята (загружена в LogonUI). Новая будет подставлена после перезагрузки.");
                else { Fail(L"Не удалось скопировать DLL в System32, ошибка " + std::to_wstring(e)); return; }
            } else { Fail(L"Не удалось скопировать DLL в System32, ошибка " + std::to_wstring(e)); return; }
        } else LogW(L"DLL скопирована в " + sys);
    }
    HMODULE h = LoadLibraryW(sys.c_str());
    if (!h) { Fail(L"Не удалось загрузить " + sys + L", ошибка " + std::to_wstring(GetLastError())); return; }
    RegFn fn = (RegFn)GetProcAddress(h, reg ? "DllRegisterServer" : "DllUnregisterServer");
    HRESULT hr = fn ? fn() : E_FAIL;
    FreeLibrary(h);
    if (FAILED(hr)) { Fail(L"Регистрация вернула ошибку 0x" + std::to_wstring((unsigned)hr)); return; }
    if (reg) LogW(L"DLL зарегистрирована. Плитка появится на экране блокировки (Win+L).");
    else {
        LogW(L"Регистрация снята.");
        if (!DeleteFileW(sys.c_str())) MoveFileExW(sys.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
    }
}

// ---------- UI plumbing ----------
static const int kButtons[] = { IDC_BTN_STATUS, IDC_BTN_PROVISION, IDC_BTN_ENROLL, IDC_BTN_DELETE, IDC_BTN_TEST, IDC_BTN_SETPW,
                                IDC_BTN_REGISTER, IDC_BTN_UNREGISTER, IDC_BTN_TOGGLE, IDC_BTN_WIPE, IDC_BTN_UNINSTALL };
static void EnableButtons(bool on) { for (int id : kButtons) EnableWindow(GetDlgItem(g_hwnd, id), on); }

static void RunOp(std::function<void()> op) {
    if (g_busy.exchange(true)) return;
    EnableButtons(false);
    std::thread([op] {
        op();
        PostMessageW(g_hwnd, WM_APP_DONE, 0, 0);
    }).detach();
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
        wchar_t name[256]; DWORD n = 256;
        if (GetUserNameW(name, &n)) SetDlgItemTextW(g_hwnd, IDC_USER, name);
        SetDlgItemTextW(g_hwnd, IDC_DOMAIN, L".");
        SetDlgItemInt(g_hwnd, IDC_FINGER, 0, FALSE);
    }
    SetDlgItemTextW(g_hwnd, IDC_PORT, cfg.port.c_str());
    SetDlgItemTextW(g_hwnd, IDC_USBID, cfg.usbId.c_str());
    SetDlgItemInt(g_hwnd, IDC_ENROLL_ID, 1, FALSE);
}

static INT_PTR CALLBACK DlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_INITDIALOG:
        g_hwnd = hwnd;
        LoadFormFromConfig();
        AppendLog(L"Порядок: 1) настроить устройство и пароль, 2) записать палец, 3) проверить, затем «Зарегистрировать DLL» и Win+L.");
        RunOp(OpStatus);
        return TRUE;
    case WM_APP_LOG: { std::unique_ptr<std::wstring> s((std::wstring*)lParam); AppendLog(*s); return TRUE; }
    case WM_APP_STATUS: { std::unique_ptr<std::wstring> s((std::wstring*)lParam); SetDlgItemTextW(hwnd, IDC_STATUS, s->c_str()); return TRUE; }
    case WM_APP_DONE:
        g_busy = false; EnableButtons(true);
        return TRUE;
    case WM_COMMAND: {
        int id = LOWORD(wParam);
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
    DialogBoxParamW(hInst, MAKEINTRESOURCEW(IDD_MAIN), nullptr, DlgProc, 0);
    return 0;
}
