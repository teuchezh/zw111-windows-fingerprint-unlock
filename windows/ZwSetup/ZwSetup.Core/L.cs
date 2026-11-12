using System.ComponentModel;
using System.Globalization;

namespace ZwSetup.Core;

public enum Lang { Ru, En }

/// <summary>Bilingual string table. Bind XAML to the indexer: {Binding [Key], Source={x:Static core:L.I}}.</summary>
public sealed class L : INotifyPropertyChanged
{
    public static readonly L I = new();
    public event PropertyChangedEventHandler? PropertyChanged;
    static Lang _lang = Detect();

    public static Lang Current => _lang;
    public static string Setting { get; private set; } = "auto";

    public static Lang Detect() => CultureInfo.CurrentUICulture.TwoLetterISOLanguageName.Equals("ru", StringComparison.OrdinalIgnoreCase) ? Lang.Ru : Lang.En;

    public static void Apply(string setting)
    {
        Setting = setting ?? "auto";
        _lang = Setting.Equals("ru", StringComparison.OrdinalIgnoreCase) ? Lang.Ru
              : Setting.Equals("en", StringComparison.OrdinalIgnoreCase) ? Lang.En : Detect();
        I.PropertyChanged?.Invoke(I, new PropertyChangedEventArgs("Item[]"));
    }

    public string this[string key] => S(key);

    public static string S(string key) => Table.TryGetValue(key, out var v) ? (_lang == Lang.Ru ? v.ru : v.en) : key;
    public static string F(string key, params object[] args) => string.Format(S(key), args);

    static readonly Dictionary<string, (string ru, string en)> Table = new()
    {
        // navigation / window
        ["AppTitle"] = ("Вход по отпечатку", "Fingerprint sign-in"),
        ["AppSubtitle"] = ("ZW111 + RP2040", "ZW111 + RP2040"),
        ["Nav_Status"] = ("Статус", "Status"),
        ["Nav_Setup"] = ("Настройка", "Setup"),
        ["Nav_Fingers"] = ("Отпечатки", "Fingerprints"),
        ["Nav_Settings"] = ("Параметры", "Settings"),
        ["Nav_Log"] = ("Журнал", "Log"),
        ["Busy"] = ("Выполняется…", "Working…"),
        // status page
        ["Status_Title"] = ("Статус", "Status"),
        ["Status_Config"] = ("Конфигурация", "Configuration"),
        ["Status_NotConfigured"] = ("Не настроено. Перейдите в «Настройка».", "Not set up. Go to \"Setup\"."),
        ["Status_ConfiguredFor"] = ("Пользователь {0}", "User {0}"),
        ["Status_Dll"] = ("Провайдер входа (ZwCredProv.dll)", "Sign-in provider (ZwCredProv.dll)"),
        ["Status_DllRegistered"] = ("Зарегистрирован в Windows", "Registered in Windows"),
        ["Status_DllNotRegistered"] = ("Не зарегистрирован", "Not registered"),
        ["Status_Device"] = ("Устройство", "Device"),
        ["Status_DeviceOn"] = ("{0}: ключи {1}, отпечатков в сканере: {2}", "{0}: keys {1}, fingerprints in the scanner: {2}"),
        ["Status_KeysYes"] = ("записаны", "provisioned"),
        ["Status_KeysNo"] = ("НЕ записаны", "NOT provisioned"),
        ["Status_DeviceOff"] = ("Не найдено", "Not found"),
        ["Status_Ports"] = ("COM-порты", "COM ports"),
        ["Status_NoPorts"] = ("Нет COM-портов", "No COM ports"),
        ["Status_Refresh"] = ("Обновить", "Refresh"),
        ["Status_Register"] = ("Зарегистрировать DLL", "Register DLL"),
        ["Status_Unregister"] = ("Снять регистрацию", "Unregister"),
        ["Status_Tile"] = ("Плитка на экране входа", "Sign-in tile"),
        ["Status_TileDesc"] = ("Выключение скрывает плитку, настройки сохраняются", "Turning it off hides the tile; settings are kept"),
        // setup page
        ["Setup_Title"] = ("Настройка", "Setup"),
        ["Setup_Account"] = ("Учётная запись Windows", "Windows account"),
        ["Setup_User"] = ("Пользователь", "User name"),
        ["Setup_UserHint"] = ("имя или почта аккаунта Microsoft", "name or Microsoft account e-mail"),
        ["Setup_Domain"] = ("Домен", "Domain"),
        ["Setup_DomainHint"] = (". для локальной записи, MicrosoftAccount для аккаунта Microsoft", ". for a local account, MicrosoftAccount for a Microsoft account"),
        ["Setup_Password"] = ("Пароль", "Password"),
        ["Setup_Password2"] = ("Повтор пароля", "Repeat password"),
        ["Setup_PasswordHint"] = ("Пароль учётной записи, не PIN", "The account password, not the PIN"),
        ["Setup_Finger"] = ("Разрешённый слот пальца", "Allowed finger slot"),
        ["Setup_FingerDesc"] = ("0 = любой записанный палец", "0 = any enrolled finger"),
        ["Setup_DeviceGroup"] = ("Устройство", "Device"),
        ["Setup_Port"] = ("COM-порт", "COM port"),
        ["Setup_PortDesc"] = ("auto = искать по USB id", "auto = search by USB id"),
        ["Setup_UsbId"] = ("USB id", "USB id"),
        ["Setup_UsbIdDesc"] = ("VID_2E8A подходит для любой платы RP2040", "VID_2E8A matches any RP2040 board"),
        ["Setup_Step1"] = ("1. Настроить устройство и пароль", "1. Set up device and password"),
        ["Setup_Step1Desc"] = ("Новые ключи, запись в устройство (держите USR/BOOT), шифрование пароля", "New keys, write to the device (hold USR/BOOT), encrypt the password"),
        ["Setup_Step3"] = ("3. Проверить", "3. Test"),
        ["Setup_Step3Desc"] = ("Приложите палец: расшифровка пароля и проверка LogonUser", "Place a finger: decrypt the password and verify with LogonUser"),
        ["Setup_ChangePw"] = ("Сменить пароль", "Change password"),
        ["Setup_ChangePwDesc"] = ("После смены пароля Windows; нужен палец", "After a Windows password change; a finger is required"),
        ["Setup_Run"] = ("Выполнить", "Run"),
        ["Setup_MsaDetected"] = ("Обнаружен аккаунт Microsoft: имя и домен подставлены. Пароль нужен от аккаунта Microsoft, не PIN.", "Microsoft account detected: name and domain filled in. Use the Microsoft account password, not the PIN."),
        // fingers page
        ["Fingers_Title"] = ("Отпечатки", "Fingerprints"),
        ["Fingers_Slot"] = ("Слот", "Slot"),
        ["Fingers_SlotDesc"] = ("Номер ячейки в сканере, 1…199", "Cell number in the scanner, 1…199"),
        ["Fingers_Enroll"] = ("2. Записать палец", "2. Enroll finger"),
        ["Fingers_EnrollDesc"] = ("Держите USR/BOOT; палец прикладывается дважды", "Hold USR/BOOT; the finger is placed twice"),
        ["Fingers_Delete"] = ("Удалить палец из слота", "Delete finger from slot"),
        ["Fingers_DeleteDesc"] = ("Держите USR/BOOT", "Hold USR/BOOT"),
        ["Fingers_Wipe"] = ("Стереть устройство", "Wipe device"),
        ["Fingers_WipeDesc"] = ("Ключи и все отпечатки; затем нужен шаг 1 заново", "Keys and all fingerprints; step 1 is needed again afterwards"),
        ["Fingers_Count"] = ("Отпечатков в сканере", "Fingerprints in the scanner"),
        // settings page
        ["Settings_Title"] = ("Параметры", "Settings"),
        ["Settings_Language"] = ("Язык", "Language"),
        ["Settings_LanguageDesc"] = ("Окно, консольная утилита и плитка на экране входа", "Window, console tool and the sign-in tile"),
        ["Settings_LangAuto"] = ("Как в Windows", "Follow Windows"),
        ["Settings_Theme"] = ("Тема", "Theme"),
        ["Settings_ThemeDesc"] = ("Оформление этого окна", "Appearance of this window"),
        ["Settings_ThemeAuto"] = ("Как в Windows", "Follow Windows"),
        ["Settings_ThemeDark"] = ("Тёмная", "Dark"),
        ["Settings_ThemeLight"] = ("Светлая", "Light"),
        ["Settings_Debug"] = ("Отладочный лог провайдера", "Provider debug log"),
        ["Settings_DebugDesc"] = ("C:\\ProgramData\\ZwCredProv\\zwcredprov.log", "C:\\ProgramData\\ZwCredProv\\zwcredprov.log"),
        ["Settings_Remove"] = ("Удалить настройки", "Remove settings"),
        ["Settings_RemoveDesc"] = ("Стирает ключ реестра; устройство и DLL не трогаются", "Deletes the registry key; device and DLL are left alone"),
        ["Settings_About"] = ("О программе", "About"),
        ["Settings_AboutDesc"] = ("github.com/teuchezh/zw111-windows-fingerprint-unlock", "github.com/teuchezh/zw111-windows-fingerprint-unlock"),
        ["Settings_NeedConfig"] = ("Сначала выполните шаг 1 в «Настройке».", "Run step 1 in \"Setup\" first."),
        // log page
        ["Log_Title"] = ("Журнал", "Log"),
        ["Log_Clear"] = ("Очистить", "Clear"),
        // dialogs
        ["Dlg_Ok"] = ("OK", "OK"),
        ["Dlg_Cancel"] = ("Отмена", "Cancel"),
        ["Dlg_Continue"] = ("Продолжить", "Continue"),
        ["Dlg_Error"] = ("Ошибка", "Error"),
        ["Dlg_Attention"] = ("Внимание", "Attention"),
        ["HoldButton"] = ("Зажмите и держите кнопку USR (или BOOT) на плате, затем нажмите OK.", "Press and hold the USR (or BOOT) button on the board, then press OK."),
        ["WipeConfirm"] = ("Будут стёрты ключи и ВСЕ отпечатки в устройстве.\nЗажмите USR (или BOOT) и нажмите OK.", "Keys and ALL fingerprints in the device will be erased.\nHold USR (or BOOT) and press OK."),
        ["RemoveConfirm"] = ("Удалить конфигурацию из реестра? Устройство не трогается.", "Remove the configuration from the registry? The device is left untouched."),
        ["PwEmptyQ"] = ("Пароль пустой. Продолжить?", "The password is empty. Continue?"),
        ["MsaOffer"] = ("Локальная запись {0} привязана к аккаунту Microsoft {1}.\nДля входа Windows требует имя MicrosoftAccount\\{1} и пароль аккаунта Microsoft (не PIN).\n\nИспользовать эти домен и имя?", "Local account {0} is linked to the Microsoft account {1}.\nWindows requires the name MicrosoftAccount\\{1} and the Microsoft account password (not the PIN).\n\nUse this domain and name?"),
        ["MsaNeedsEmail"] = ("Для домена MicrosoftAccount имя пользователя должно быть почтой аккаунта (name@outlook.com).\nПродолжить всё равно?", "For the MicrosoftAccount domain the user name must be the account e-mail (name@outlook.com).\nContinue anyway?"),
        ["AccountNotFound"] = ("Учётная запись {0} не найдена.\nДля аккаунта Microsoft укажите домен MicrosoftAccount и почту как имя.\nПродолжить всё равно?", "Account {0} was not found.\nFor a Microsoft account use domain MicrosoftAccount and the e-mail as the user name.\nContinue anyway?"),
        // operation messages
        ["DeviceFoundOn"] = ("Устройство найдено на {0}", "Device found on {0}"),
        ["DeviceNotFound"] = ("Устройство не найдено (порт {0}, USB id {1}).\n{2}", "Device not found (port {0}, USB id {1}).\n{2}"),
        ["NoPortsWithId"] = ("нет COM-портов с USB id ", "no COM ports with USB id "),
        ["PortOpenFailed"] = (": не открывается: ", ": cannot be opened: "),
        ["PortBusy"] = (": порт занят другой программой (закройте монитор PlatformIO / Arduino)", ": port is in use by another program (close the PlatformIO / Arduino monitor)"),
        ["PortNoHello"] = (": открыт, но нет ответа на HELLO (", ": opened, but no reply to HELLO ("),
        ["PortNoHello2"] = ("). Прошивка залита?", "). Is the firmware flashed?"),
        ["PlaceFinger"] = ("Приложите палец к сканеру…", "Place your finger on the scanner…"),
        ["NoMatchRetry"] = ("Палец не распознан, ещё раз.", "Finger not recognized, try again."),
        ["MatchId"] = ("Совпадение: палец #{0}", "Match: finger #{0}"),
        ["ErrComm"] = ("Ошибка связи с устройством: {0}", "Device communication error: {0}"),
        ["ErrNotProvisioned"] = ("Устройство не настроено: выполните шаг 1.", "The device is not provisioned: run step 1."),
        ["ErrAuthFailed"] = ("Устройство отклонило ключ. Устройство и ПК настроены разными ключами: повторите шаг 1.", "The device rejected the key. Device and PC hold different keys: repeat step 1."),
        ["ErrTimeout"] = ("Палец не приложен вовремя.", "No finger was presented in time."),
        ["ErrProtocol"] = ("Ошибка протокола: {0}", "Protocol error: {0}"),
        ["ErrUserEmpty"] = ("Укажите имя пользователя.", "Enter a user name."),
        ["ErrPwMismatch"] = ("Пароли не совпадают.", "Passwords do not match."),
        ["ErrSlot"] = ("Укажите слот пальца от 1 до 199.", "Enter a finger slot from 1 to 199."),
        ["ErrUnprotect"] = ("Не удалось расшифровать конфигурацию. Повторите шаг 1.", "Failed to decrypt the configuration. Repeat step 1."),
        ["ErrSave"] = ("Ошибка записи конфигурации: {0}", "Failed to save the configuration: {0}"),
        ["DeviceRefused"] = ("Устройство отказало: {0}\nКнопка была зажата в момент подтверждения?", "The device refused: {0}\nWas the button held while confirming?"),
        ["KeysWritten"] = ("Ключи записаны в устройство. Кнопку можно отпустить.", "Keys written to the device. You can release the button."),
        ["CfgSaved"] = ("Конфигурация сохранена в реестре (доступ только SYSTEM и администраторам).", "Configuration saved to the registry (readable only by SYSTEM and administrators)."),
        ["NoTemplates"] = ("В сканере нет отпечатков: выполните шаг 2 в «Отпечатках».", "The scanner holds no fingerprints: run step 2 in \"Fingerprints\"."),
        ["TemplatesN"] = ("В сканере отпечатков: {0}. Можно переходить к шагу 3.", "Fingerprints in the scanner: {0}. You can proceed to step 3."),
        ["DllNotRegHint"] = ("DLL ещё не зарегистрирована: нажмите «Зарегистрировать DLL» на странице «Статус».", "The DLL is not registered yet: click \"Register DLL\" on the Status page."),
        ["EnrollPlace"] = ("Приложите палец (кнопку можно отпустить)…", "Place your finger (you can release the button)…"),
        ["EnrollRemove"] = ("Уберите палец…", "Remove your finger…"),
        ["EnrollAgain"] = ("Приложите тот же палец ещё раз…", "Place the same finger again…"),
        ["EnrollErr"] = ("Ошибка записи пальца: {0}", "Enrollment error: {0}"),
        ["Enrolled"] = ("Палец записан в слот {0}.", "Finger enrolled in slot {0}."),
        ["DeleteErr"] = ("Ошибка удаления: {0}", "Delete error: {0}"),
        ["SlotDeleted"] = ("Слот {0} удалён.", "Slot {0} deleted."),
        ["PwDecrypted"] = ("Пароль расшифрован. Проверяю через LogonUser…", "Password decrypted. Verifying with LogonUser…"),
        ["PwNotDecrypted"] = ("Пароль не расшифрован: ключи устройства и ПК не совпадают. Повторите шаг 1.", "Password could not be decrypted: device and PC keys differ. Repeat step 1."),
        ["LogonOk"] = ("LogonUser: OK. Всё готово: нажмите Win+L и приложите палец.", "LogonUser: OK. All set: press Win+L and place your finger."),
        ["LogonFail"] = ("LogonUser не удался, ошибка {0} (1326 = неверные имя или пароль). Windows отвергнет эту пару и на экране входа.", "LogonUser failed, error {0} (1326 = bad user name or password). Windows will reject this pair on the sign-in screen too."),
        ["MsaLinkedFix"] = ("Запись {0} привязана к аккаунту Microsoft {1}: повторите шаг 1 с доменом MicrosoftAccount, именем {1} и паролем аккаунта Microsoft.", "Account {0} is linked to the Microsoft account {1}: repeat step 1 with domain MicrosoftAccount, user name {1} and the Microsoft account password."),
        ["PwHint"] = ("Проверьте пароль и повторите «Сменить пароль». Для аккаунта Microsoft должен быть выключен беспарольный вход.", "Check the password and use \"Change password\". For a Microsoft account, passwordless sign-in must be disabled."),
        ["PwUpdated"] = ("Пароль обновлён.", "Password updated."),
        ["TileOn"] = ("Плитка включена.", "Tile enabled."),
        ["TileOff"] = ("Плитка выключена (настройки сохранены).", "Tile disabled (settings kept)."),
        ["Wiped"] = ("Устройство очищено.", "Device wiped."),
        ["CfgDeleted"] = ("Конфигурация удалена.", "Configuration removed."),
        ["NothingToDelete"] = ("Нечего удалять.", "Nothing to remove."),
        ["DllMissing"] = ("Рядом с программой нет ZwCredProv.dll:\n{0}", "ZwCredProv.dll is not next to the program:\n{0}"),
        ["DllBusyReboot"] = ("Старая DLL занята (загружена в LogonUI). Новая будет подставлена после перезагрузки.", "The old DLL is in use (loaded by LogonUI). The new one will replace it after a reboot."),
        ["DllCopyFail"] = ("Не удалось скопировать DLL в System32: {0}", "Failed to copy the DLL to System32: {0}"),
        ["DllCopied"] = ("DLL скопирована в {0}", "DLL copied to {0}"),
        ["DllRegHr"] = ("Регистрация вернула ошибку 0x{0:X8}", "Registration returned error 0x{0:X8}"),
        ["DllRegistered"] = ("DLL зарегистрирована. Плитка появится на экране блокировки (Win+L).", "DLL registered. The tile will appear on the lock screen (Win+L)."),
        ["DllUnregistered"] = ("Регистрация снята.", "Registration removed."),
        ["Intro"] = ("Порядок: 1) «Настройка», 2) «Отпечатки», 3) проверка, затем «Зарегистрировать DLL» на странице «Статус» и Win+L.", "Order: 1) \"Setup\", 2) \"Fingerprints\", 3) test, then \"Register DLL\" on the Status page and Win+L."),
        ["NotAdmin"] = ("Программа запущена без прав администратора: запись в реестр и регистрация DLL не сработают.", "Running without administrator rights: registry writes and DLL registration will fail."),
        ["LangSaved"] = ("Язык сохранён; он также применяется к плитке на экране входа.", "Language saved; it also applies to the sign-in tile."),
    };
}
