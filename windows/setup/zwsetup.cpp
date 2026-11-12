// zwsetup: provisioning / enrollment / diagnostics for ZwCredProv. Run as Administrator.
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

using namespace zw;

static void usage() {
    wprintf(
L"zwsetup — настройка входа в Windows по отпечатку (ZW111 + RP2040)\n\n"
L"  zwsetup provision --user ИМЯ [--domain ДОМЕН|.] [--port COMn|auto] [--finger N] [--debug]\n"
L"        Полная настройка: новые ключи, прошивка ключей в устройство (держите BOOTSEL!),\n"
L"        запрос пароля и запись зашифрованной конфигурации в реестр.\n"
L"  zwsetup enroll --id N [--port COMn|auto]       Записать палец в слот N (держите BOOTSEL)\n"
L"  zwsetup delete --id N [--port COMn|auto]       Удалить палец из слота N (держите BOOTSEL)\n"
L"  zwsetup test [--port COMn|auto]                Проверить всю цепочку без входа в систему\n"
L"  zwsetup set-password [--port COMn|auto]        Сменить сохранённый пароль (нужен палец)\n"
L"  zwsetup status                                  Показать конфигурацию и найти устройство\n"
L"  zwsetup wipe [--port COMn|auto]                 Стереть ключи и все отпечатки в устройстве\n"
L"  zwsetup disable | enable                        Временно выключить/включить плитку входа\n"
L"  zwsetup uninstall                               Удалить конфигурацию из реестра\n");
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
        wprintf(L"Устройство не найдено (порт: %ls, USB id: %ls).\n%ls", p.c_str(), cfg.usbId.c_str(), diag.c_str());
        return false;
    }
    wprintf(L"Устройство найдено на %ls\n", chosen.c_str());
    return true;
}

static void PrintAuthResult(AuthResult r, const std::string& err) {
    switch (r) {
    case AuthResult::Match: break;
    case AuthResult::NoDevice: wprintf(L"Ошибка связи с устройством: %ls\n", A2W(err).c_str()); break;
    case AuthResult::NotProvisioned: wprintf(L"Устройство не настроено: выполните zwsetup provision.\n"); break;
    case AuthResult::AuthFailed: wprintf(L"Устройство отклонило ключ K_auth. Устройство и ПК настроены разными ключами: выполните zwsetup provision.\n"); break;
    case AuthResult::Timeout: wprintf(L"Палец не приложен вовремя.\n"); break;
    case AuthResult::Cancelled: wprintf(L"Отменено.\n"); break;
    case AuthResult::Error: wprintf(L"Ошибка протокола: %ls\n", A2W(err).c_str()); break;
    }
}

// Runs the handshake and returns the decrypted K_dev (used by test and set-password).
static bool AuthGetKdev(SerialPort& port, const Secrets& s, uint8_t kdev[32]) {
    std::atomic<bool> cancel{false}; int id = 0; std::string err;
    AuthResult r = RunAuth(port, s.kauth, cancel, kdev, id, &err, [](const std::string& ev) {
        if (ev == "WAIT") wprintf(L"Приложите палец к сканеру...\n");
        else if (ev == "NOMATCH") wprintf(L"Палец не распознан, ещё раз.\n");
    });
    PrintAuthResult(r, err);
    if (r != AuthResult::Match) return false;
    wprintf(L"Совпадение: палец #%d\n", id);
    return true;
}

static int CmdProvision(int argc, wchar_t** argv) {
    Config cfg; LoadConfig(cfg);     // keep existing port/usbId if any
    std::wstring user = Arg(argc, argv, L"--user");
    if (user.empty()) { wprintf(L"Нужен --user\n"); return 2; }
    cfg.user = user;
    cfg.domain = Arg(argc, argv, L"--domain", L".");
    std::wstring port = Arg(argc, argv, L"--port"); if (!port.empty()) cfg.port = port;
    std::wstring usb = Arg(argc, argv, L"--usbid"); if (!usb.empty()) cfg.usbId = usb;
    cfg.fingerId = _wtoi(Arg(argc, argv, L"--finger", L"0").c_str());
    cfg.debug = Flag(argc, argv, L"--debug");
    cfg.enabled = true;

    // Check the account exists before touching anything.
    std::wstring qualified = EffectiveDomain(cfg) + L"\\" + cfg.user;
    BYTE sid[SECURITY_MAX_SID_SIZE]; DWORD cb = sizeof(sid); wchar_t dom[256]; DWORD cd = 256; SID_NAME_USE use;
    if (!LookupAccountNameW(nullptr, qualified.c_str(), sid, &cb, dom, &cd, &use))
        wprintf(L"Предупреждение: учётная запись %ls не найдена через LookupAccountName. Для аккаунта Microsoft используйте --domain MicrosoftAccount --user почта.\n", qualified.c_str());
    if (_wcsicmp(cfg.domain.c_str(), L"MicrosoftAccount") == 0 && cfg.user.find(L'@') == std::wstring::npos)
        wprintf(L"Предупреждение: для домена MicrosoftAccount имя пользователя должно быть почтой аккаунта (name@outlook.com).\n");
    else wprintf(L"Учётная запись: %ls\n", qualified.c_str());

    SerialPort dev;
    if (!OpenCfgDevice(dev, cfg, L"")) return 1;

    std::wstring pw = ReadPassword(L"Пароль учётной записи Windows: ");
    std::wstring pw2 = ReadPassword(L"Повторите пароль: ");
    if (pw != pw2) { wprintf(L"Пароли не совпадают.\n"); return 1; }

    Secrets s; uint8_t kdev[32];
    if (!RandomBytes(kdev, 32) || !RandomBytes(s.kpc, 32) || !RandomBytes(s.kauth, 32)) { wprintf(L"RNG error\n"); return 1; }

    wprintf(L"\nЗажмите и держите кнопку USR (или BOOT) на плате, затем нажмите Enter...");
    getwchar();
    std::string err;
    if (!Provision(dev, kdev, s.kauth, &err)) {
        wprintf(L"Устройство отказало: %ls (кнопка USR/BOOT была зажата?)\n", A2W(err).c_str());
        SecureZeroMemory(kdev, 32); return 1;
    }
    wprintf(L"Ключи записаны в устройство. Можно отпустить кнопку.\n");

    if (!SealPassword(s, kdev, pw)) { wprintf(L"Ошибка шифрования\n"); SecureZeroMemory(kdev, 32); return 1; }
    SecureZeroMemory(kdev, 32);
    SecureZeroMemory(&pw[0], pw.size() * 2); SecureZeroMemory(&pw2[0], pw2.size() * 2);

    std::wstring werr;
    if (!ProtectSecrets(s, cfg.blob, &werr) || !SaveConfig(cfg, &werr)) { wprintf(L"Ошибка записи конфигурации: %ls\n", werr.c_str()); return 1; }
    wprintf(L"Конфигурация сохранена в HKLM\\%ls (доступ только SYSTEM и администраторам).\n", kRegPath);

    DeviceInfo info; Hello(dev, info);
    if (info.templates == 0) wprintf(L"\nВ сканере нет отпечатков. Запишите палец: zwsetup enroll --id 1\n");
    else wprintf(L"\nВ сканере %d отпечатков. Проверьте: zwsetup test\n", info.templates);
    wprintf(L"Не забудьте зарегистрировать DLL: regsvr32 ZwCredProv.dll\n");
    return 0;
}

static int CmdEnroll(int argc, wchar_t** argv, bool del) {
    Config cfg; LoadConfig(cfg);
    int id = _wtoi(Arg(argc, argv, L"--id", L"0").c_str());
    if (id <= 0) { wprintf(L"Нужен --id N (1..199)\n"); return 2; }
    SerialPort dev;
    if (!OpenCfgDevice(dev, cfg, Arg(argc, argv, L"--port"))) return 1;
    wprintf(L"Зажмите и держите USR (или BOOT), затем нажмите Enter...");
    getwchar();
    std::string err;
    if (del) {
        if (!DeleteFinger(dev, id, &err)) { wprintf(L"Ошибка: %ls\n", A2W(err).c_str()); return 1; }
        wprintf(L"Слот %d удалён.\n", id); return 0;
    }
    bool ok = Enroll(dev, id, [](const std::string& ev) {
        if (ev == "PLACE") wprintf(L"Приложите палец (кнопку можно отпустить)...\n");
        else if (ev == "REMOVE") wprintf(L"Уберите палец...\n");
        else if (ev == "AGAIN") wprintf(L"Приложите тот же палец ещё раз...\n");
    }, &err);
    if (!ok) { wprintf(L"Ошибка записи: %ls\n", A2W(err).c_str()); return 1; }
    wprintf(L"Палец записан в слот %d.\n", id);
    return 0;
}

static int CmdTest(int argc, wchar_t** argv) {
    Config cfg; std::wstring werr;
    if (!LoadConfig(cfg, &werr)) { wprintf(L"%ls\n", werr.c_str()); return 1; }
    Secrets s;
    if (!UnprotectSecrets(cfg.blob, s, &werr)) { wprintf(L"Не удалось расшифровать Blob: %ls\n", werr.c_str()); return 1; }
    SerialPort dev;
    if (!OpenCfgDevice(dev, cfg, Arg(argc, argv, L"--port"))) return 1;
    uint8_t kdev[32];
    if (!AuthGetKdev(dev, s, kdev)) return 1;
    std::wstring pw;
    bool ok = OpenPassword(s, kdev, pw);
    SecureZeroMemory(kdev, 32);
    if (!ok) { wprintf(L"Пароль НЕ расшифрован: ключи устройства и ПК не совпадают. Выполните zwsetup provision.\n"); return 1; }
    wprintf(L"Пароль успешно расшифрован (длина %u). Проверяю через LogonUser...\n", (unsigned)pw.size());
    HANDLE tok = nullptr;
    std::wstring dom = EffectiveDomain(cfg);
    if (LogonUserW(cfg.user.c_str(), dom.c_str(), pw.c_str(), LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &tok)) {
        wprintf(L"LogonUser: OK. Всё готово.\n"); CloseHandle(tok);
    } else {
        wprintf(L"LogonUser не удался (ошибка %lu). Для локальных аккаунтов это значит неверный пароль; для аккаунтов Microsoft LogonUser может не работать, проверьте на экране блокировки.\n", GetLastError());
    }
    SecureZeroMemory(&pw[0], pw.size() * 2);
    return 0;
}

static int CmdSetPassword(int argc, wchar_t** argv) {
    Config cfg; std::wstring werr;
    if (!LoadConfig(cfg, &werr)) { wprintf(L"%ls\n", werr.c_str()); return 1; }
    Secrets s;
    if (!UnprotectSecrets(cfg.blob, s, &werr)) { wprintf(L"Не удалось расшифровать Blob: %ls\n", werr.c_str()); return 1; }
    SerialPort dev;
    if (!OpenCfgDevice(dev, cfg, Arg(argc, argv, L"--port"))) return 1;
    std::wstring pw = ReadPassword(L"Новый пароль Windows: ");
    std::wstring pw2 = ReadPassword(L"Повторите: ");
    if (pw != pw2) { wprintf(L"Пароли не совпадают.\n"); return 1; }
    uint8_t kdev[32];
    if (!AuthGetKdev(dev, s, kdev)) return 1;
    bool ok = SealPassword(s, kdev, pw);
    SecureZeroMemory(kdev, 32); SecureZeroMemory(&pw[0], pw.size() * 2); SecureZeroMemory(&pw2[0], pw2.size() * 2);
    if (!ok || !ProtectSecrets(s, cfg.blob, &werr) || !SaveConfig(cfg, &werr)) { wprintf(L"Ошибка: %ls\n", werr.c_str()); return 1; }
    wprintf(L"Пароль обновлён.\n");
    return 0;
}

static int CmdStatus() {
    Config cfg; std::wstring werr;
    bool ok = LoadConfig(cfg, &werr);
    wprintf(L"Конфигурация: %ls\n", ok ? L"OK" : werr.c_str());
    if (ok) wprintf(L"  User=%ls Domain=%ls (%ls) Port=%ls UsbId=%ls FingerId=%lu Enabled=%d Debug=%d\n",
        cfg.user.c_str(), cfg.domain.c_str(), EffectiveDomain(cfg).c_str(), cfg.port.c_str(), cfg.usbId.c_str(), cfg.fingerId, (int)cfg.enabled, (int)cfg.debug);
    auto all = ListComPorts();
    wprintf(L"Все COM-порты в системе:%ls\n", all.empty() ? L" нет" : L"");
    for (auto& p : all) wprintf(L"  %-6ls %ls\n", p.first.c_str(), p.second.c_str());
    auto ports = FindComPortsByUsbId(cfg.usbId);
    wprintf(L"Из них с USB id %ls: %ls\n", cfg.usbId.c_str(), ports.empty() ? L"нет" : L"");
    for (auto& p : ports) wprintf(L"  %ls\n", p.c_str());
    if (ports.empty() && !all.empty())
        wprintf(L"Подсказка: найдите выше строку своей платы (VID_2E8A для RP2040) и передайте её id:\n"
                L"  zwsetup provision --user ИМЯ --usbid \"VID_xxxx&PID_xxxx\"   (или --port COMn)\n");
    SerialPort dev; std::wstring chosen, diag;
    if (OpenDevice(dev, cfg.port, cfg.usbId, &chosen, &diag)) {
        DeviceInfo info; Hello(dev, info);
        wprintf(L"Устройство на %ls: provisioned=%d, отпечатков=%d\n", chosen.c_str(), (int)info.provisioned, info.templates);
    } else wprintf(L"Устройство не отвечает:\n%ls", diag.c_str());
    HKEY k;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\{7B2F3C1E-9A4D-4E6B-8C21-5D0E9F3A6B47}", 0, KEY_READ | KEY_WOW64_64KEY, &k) == ERROR_SUCCESS) {
        wprintf(L"ZwCredProv.dll зарегистрирована.\n"); RegCloseKey(k);
    } else wprintf(L"ZwCredProv.dll НЕ зарегистрирована (regsvr32 ZwCredProv.dll).\n");
    return 0;
}

static int CmdEnable(bool on) {
    Config cfg; std::wstring werr;
    if (!LoadConfig(cfg, &werr)) { wprintf(L"%ls\n", werr.c_str()); return 1; }
    cfg.enabled = on;
    if (!SaveConfig(cfg, &werr)) { wprintf(L"%ls\n", werr.c_str()); return 1; }
    wprintf(L"Enabled=%d\n", (int)on); return 0;
}

static int CmdWipe(int argc, wchar_t** argv) {
    Config cfg; LoadConfig(cfg);
    SerialPort dev;
    if (!OpenCfgDevice(dev, cfg, Arg(argc, argv, L"--port"))) return 1;
    wprintf(L"Будут стёрты ключи и ВСЕ отпечатки. Зажмите USR (или BOOT) и нажмите Enter...");
    getwchar();
    std::string err;
    if (!Wipe(dev, &err)) { wprintf(L"Ошибка: %ls\n", A2W(err).c_str()); return 1; }
    wprintf(L"Устройство очищено.\n"); return 0;
}

int wmain(int argc, wchar_t** argv) {
    _setmode(_fileno(stdout), _O_U16TEXT);
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
    if (cmd == L"wipe") return CmdWipe(argc, argv);
    if (cmd == L"uninstall") { wprintf(DeleteConfig() ? L"Конфигурация удалена. Снимите регистрацию DLL: regsvr32 /u ZwCredProv.dll\n" : L"Нечего удалять.\n"); return 0; }
    usage(); return 2;
}
