// Two-language string table (Russian / English) shared by the credential provider and the setup tools.
// Language: config value Lang = "auto" | "ru" | "en"; "auto" follows the Windows UI language.
#pragma once
#include <windows.h>
#include <string>

namespace zw {

enum class Lang { Ru, En };

// X(ID, russian, english)
#define ZW_STRINGS(X) \
/* --- credential provider tile --- */ \
X(CP_LABEL,            L"Отпечаток пальца", L"Fingerprint") \
X(CP_SUBMIT,           L"Войти", L"Sign in") \
X(CP_CONNECTING,       L"Подключение к сканеру…", L"Connecting to the scanner…") \
X(CP_TOUCH,            L"Приложите палец к сканеру", L"Place your finger on the scanner") \
X(CP_NOMATCH,          L"Палец не распознан, попробуйте ещё раз", L"Finger not recognized, try again") \
X(CP_MATCHED,          L"Отпечаток распознан, выполняется вход…", L"Fingerprint recognized, signing in…") \
X(CP_NO_DEVICE,        L"Сканер не подключён", L"Scanner not connected") \
X(CP_DEVICE_LOST,      L"Сканер отключён", L"Scanner disconnected") \
X(CP_SVC_DOWN,         L"Служба ZwCredSvc не запущена: включите вход в окнах Windows Security в ZwSetup", L"The ZwCredSvc service is not running: enable sign-in in Windows Security prompts in ZwSetup") \
X(CP_SVC_REFUSED,      L"Служба отказала: это окно или пользователь не разрешены", L"The service refused: this prompt or user is not allowed") \
X(CP_FINGER_DENIED2,   L"Этот палец не разрешён для входа", L"This finger is not allowed to sign in") \
X(CP_LOCKED_FMT,       L"Слишком много неверных попыток. Сканер заблокирован на %u с", L"Too many wrong fingers. The scanner is locked for %u s") \
X(CP_CFG_ERROR,        L"Ошибка конфигурации: ", L"Configuration error: ") \
X(CP_FINGER_DENIED,    L"Этот палец не разрешён для входа", L"This finger is not allowed to sign in") \
X(CP_KEY_MISMATCH,     L"Устройство не соответствует этому ПК. Повторите шаг 1 в zwsetup-gui.", L"This device does not match this PC. Repeat step 1 in zwsetup-gui.") \
X(CP_AUTH_FAILED,      L"Устройство не принимает этот ПК (ключ K_auth). Повторите шаг 1 в zwsetup-gui.", L"The device rejects this PC (K_auth). Repeat step 1 in zwsetup-gui.") \
X(CP_NOT_PROVISIONED,  L"Устройство не настроено. Выполните шаг 1 в zwsetup-gui.", L"The device is not provisioned. Run step 1 in zwsetup-gui.") \
X(CP_LOGON_BAD_CRED,   L"Windows не приняла имя или пароль (0xC000006D). Проверьте учётную запись и пароль в zwsetup-gui, кнопка «3. Проверить».", L"Windows rejected the user name or password (0xC000006D). Check the account and password in zwsetup-gui, button \"3. Test\".") \
X(CP_LOGON_FAILED_FMT, L"Вход не выполнен (0x%08X). Проверьте настройку в zwsetup-gui, кнопка «3. Проверить».", L"Logon failed (0x%08X). Check the setup in zwsetup-gui, button \"3. Test\".") \
/* --- shared setup messages --- */ \
X(DEVICE_FOUND_ON,     L"Устройство найдено на ", L"Device found on ") \
X(DEVICE_NOT_FOUND,    L"Устройство не найдено (порт %ls, USB id %ls).", L"Device not found (port %ls, USB id %ls).") \
X(NO_PORTS_WITH_ID,    L"нет COM-портов с USB id ", L"no COM ports with USB id ") \
X(PORT_OPEN_FAILED,    L": не открывается, ошибка ", L": cannot be opened, error ") \
X(PORT_BUSY,           L" (порт занят другой программой: закройте монитор PlatformIO / Arduino)", L" (port is in use by another program: close the PlatformIO / Arduino monitor)") \
X(PORT_GONE,           L" (порт исчез)", L" (port disappeared)") \
X(PORT_NO_HELLO,       L": открыт, но нет ответа на HELLO (", L": opened, but no reply to HELLO (") \
X(PORT_NO_HELLO2,      L"). Прошивка залита? Проверьте в мониторе.", L"). Is the firmware flashed? Check in a serial monitor.") \
X(HOLD_BUTTON,         L"Зажмите и держите кнопку USR (или BOOT) на плате, затем нажмите OK.", L"Press and hold the USR (or BOOT) button on the board, then press OK.") \
X(HOLD_BUTTON_ENTER,   L"Зажмите и держите кнопку USR (или BOOT) на плате, затем нажмите Enter...", L"Press and hold the USR (or BOOT) button on the board, then press Enter...") \
X(PLACE_FINGER,        L"Приложите палец к сканеру...", L"Place your finger on the scanner...") \
X(NOMATCH_RETRY,       L"Палец не распознан, ещё раз.", L"Finger not recognized, try again.") \
X(LOCKED_FMT,          L"Слишком много неверных попыток, сканер заблокирован на %u с.", L"Too many wrong fingers, the scanner is locked for %u s.") \
X(MATCH_ID,            L"Совпадение: палец #", L"Match: finger #") \
X(ERR_COMM,            L"Ошибка связи с устройством: ", L"Device communication error: ") \
X(ERR_NOT_PROVISIONED, L"Устройство не настроено: выполните шаг 1.", L"The device is not provisioned: run step 1.") \
X(ERR_AUTH_FAILED,     L"Устройство отклонило ключ. Устройство и ПК настроены разными ключами: повторите шаг 1.", L"The device rejected the key. Device and PC hold different keys: repeat step 1.") \
X(ERR_TIMEOUT,         L"Палец не приложен вовремя.", L"No finger was presented in time.") \
X(ERR_PROTOCOL,        L"Ошибка протокола: ", L"Protocol error: ") \
X(ERR_RNG,             L"Ошибка генератора случайных чисел", L"Random number generator error") \
X(ERR_ENCRYPT,         L"Ошибка шифрования пароля", L"Password encryption error") \
X(ERR_SAVE_CFG,        L"Ошибка записи конфигурации: ", L"Failed to save configuration: ") \
X(ERR_UNPROTECT,       L"Не удалось расшифровать конфигурацию: ", L"Failed to decrypt configuration: ") \
X(ERR_PW_MISMATCH,     L"Пароли не совпадают.", L"Passwords do not match.") \
X(ERR_USER_EMPTY,      L"Укажите имя пользователя.", L"Enter a user name.") \
X(ERR_SLOT_RANGE,      L"Укажите слот пальца от 1 до 199.", L"Enter a finger slot from 1 to 199.") \
X(DEVICE_REFUSED,      L"Устройство отказало: ", L"The device refused: ") \
X(BUTTON_HELD_Q,       L"\nКнопка была зажата в момент подтверждения?", L"\nWas the button held while confirming?") \
X(KEYS_WRITTEN,        L"Ключи записаны в устройство. Кнопку можно отпустить.", L"Keys written to the device. You can release the button.") \
X(CFG_SAVED,           L"Конфигурация сохранена в реестре (доступ только SYSTEM и администраторам).", L"Configuration saved to the registry (readable only by SYSTEM and administrators).") \
X(NO_TEMPLATES,        L"В сканере нет отпечатков: выполните шаг 2.", L"The scanner holds no fingerprints: run step 2.") \
X(TEMPLATES_N,         L"В сканере отпечатков: ", L"Fingerprints in the scanner: ") \
X(GO_STEP3,            L". Можно переходить к шагу 3.", L". You can proceed to step 3.") \
X(DLL_NOT_REG_HINT,    L"DLL ещё не зарегистрирована: нажмите «Зарегистрировать DLL».", L"The DLL is not registered yet: click \"Register DLL\".") \
X(DLL_NOT_REG_CLI,     L"Не забудьте зарегистрировать DLL: regsvr32 ZwCredProv.dll", L"Remember to register the DLL: regsvr32 ZwCredProv.dll") \
X(ENROLL_PLACE,        L"Приложите палец (кнопку можно отпустить)...", L"Place your finger (you can release the button)...") \
X(ENROLL_REMOVE,       L"Уберите палец...", L"Remove your finger...") \
X(ENROLL_AGAIN,        L"Приложите тот же палец ещё раз...", L"Place the same finger again...") \
X(ENROLL_ERR,          L"Ошибка записи пальца: ", L"Enrollment error: ") \
X(ENROLLED_SLOT,       L"Палец записан в слот ", L"Finger enrolled in slot ") \
X(DELETE_ERR,          L"Ошибка удаления: ", L"Delete error: ") \
X(SLOT_DELETED_A,      L"Слот ", L"Slot ") \
X(SLOT_DELETED_B,      L" удалён.", L" deleted.") \
X(PW_DECRYPTED,        L"Пароль расшифрован. Проверяю через LogonUser...", L"Password decrypted. Verifying with LogonUser...") \
X(PW_NOT_DECRYPTED,    L"Пароль не расшифрован: ключи устройства и ПК не совпадают. Повторите шаг 1.", L"Password could not be decrypted: device and PC keys differ. Repeat step 1.") \
X(LOGON_OK,            L"LogonUser: OK. Всё готово: нажмите Win+L и приложите палец.", L"LogonUser: OK. All set: press Win+L and place your finger.") \
X(LOGON_FAIL_A,        L"LogonUser не удался, ошибка ", L"LogonUser failed, error ") \
X(LOGON_FAIL_B,        L" (1326 = неверные имя или пароль). Windows отвергнет эту пару и на экране входа.", L" (1326 = bad user name or password). Windows will reject this pair on the sign-in screen too.") \
X(MSA_LINKED_A,        L"Запись ", L"Account ") \
X(MSA_LINKED_B,        L" привязана к аккаунту Microsoft ", L" is linked to the Microsoft account ") \
X(MSA_LINKED_FIX,      L": повторите шаг 1 с доменом MicrosoftAccount, именем ", L": repeat step 1 with domain MicrosoftAccount, user name ") \
X(MSA_LINKED_FIX2,     L" и паролем аккаунта Microsoft.", L" and the Microsoft account password.") \
X(PW_HINT,             L"Проверьте пароль и повторите «Сменить пароль». Для аккаунта Microsoft в его настройках безопасности должен быть выключен беспарольный вход.", L"Check the password and use \"Change password\". For a Microsoft account, passwordless sign-in must be disabled in its security settings.") \
X(MSA_OFFER_A,         L".\nДля входа Windows требует имя в виде MicrosoftAccount\\", L".\nWindows requires the name in the form MicrosoftAccount\\") \
X(MSA_OFFER_B,         L" и пароль аккаунта Microsoft (не PIN).\n\nИспользовать эти домен и имя? (Отмена: оставить как есть)", L" and the Microsoft account password (not the PIN).\n\nUse this domain and name? (Cancel keeps the current values)") \
X(MSA_USING,           L"Используется учётная запись MicrosoftAccount\\", L"Using account MicrosoftAccount\\") \
X(MSA_CLI_USING,       L"Запись %ls привязана к аккаунту Microsoft %ls. Использую MicrosoftAccount\\%ls (пароль нужен от аккаунта Microsoft, не PIN).\n", L"Account %ls is linked to the Microsoft account %ls. Using MicrosoftAccount\\%ls (the Microsoft account password is required, not the PIN).\n") \
X(MSA_NEEDS_EMAIL,     L"Для домена MicrosoftAccount имя пользователя должно быть почтой аккаунта (name@outlook.com).", L"For the MicrosoftAccount domain the user name must be the account e-mail (name@outlook.com).") \
X(CONTINUE_ANYWAY,     L"\nПродолжить всё равно?", L"\nContinue anyway?") \
X(ACCOUNT_IS,          L"Учётная запись: ", L"Account: ") \
X(ACCOUNT_NOT_FOUND,   L"Учётная запись %ls не найдена.", L"Account %ls was not found.") \
X(ACCOUNT_MSA_HINT,    L"\nДля аккаунта Microsoft укажите домен MicrosoftAccount и почту как имя.", L"\nFor a Microsoft account use domain MicrosoftAccount and the e-mail as the user name.") \
X(PW_EMPTY_Q,          L"Пароль пустой. Продолжить?", L"The password is empty. Continue?") \
X(PW_UPDATED,          L"Пароль обновлён.", L"Password updated.") \
X(TILE_ON,             L"Плитка включена.", L"Tile enabled.") \
X(TILE_OFF,            L"Плитка выключена (настройки сохранены).", L"Tile disabled (settings kept).") \
X(WIPE_CONFIRM,        L"Будут стёрты ключи и ВСЕ отпечатки в устройстве.\nЗажмите USR (или BOOT) и нажмите OK.", L"Keys and ALL fingerprints in the device will be erased.\nHold USR (or BOOT) and press OK.") \
X(WIPE_CONFIRM_CLI,    L"Будут стёрты ключи и ВСЕ отпечатки. Зажмите USR (или BOOT) и нажмите Enter...", L"Keys and ALL fingerprints will be erased. Hold USR (or BOOT) and press Enter...") \
X(WIPED,               L"Устройство очищено.", L"Device wiped.") \
X(UNINSTALL_CONFIRM,   L"Удалить конфигурацию из реестра? Устройство не трогается.", L"Remove the configuration from the registry? The device is left untouched.") \
X(CFG_DELETED,         L"Конфигурация удалена.", L"Configuration removed.") \
X(NOTHING_TO_DELETE,   L"Нечего удалять.", L"Nothing to remove.") \
X(DLL_STILL_REG,       L"DLL всё ещё зарегистрирована: при необходимости нажмите «Снять регистрацию DLL».", L"The DLL is still registered: click \"Unregister DLL\" if needed.") \
X(DLL_MISSING,         L"Рядом с программой нет ZwCredProv.dll:\n", L"ZwCredProv.dll is not next to the program:\n") \
X(DLL_BUSY_REBOOT,     L"Старая DLL занята (загружена в LogonUI). Новая будет подставлена после перезагрузки.", L"The old DLL is in use (loaded by LogonUI). The new one will replace it after a reboot.") \
X(DLL_COPY_FAIL,       L"Не удалось скопировать DLL в System32, ошибка ", L"Failed to copy the DLL to System32, error ") \
X(DLL_COPIED,          L"DLL скопирована в ", L"DLL copied to ") \
X(DLL_LOAD_FAIL,       L"Не удалось загрузить ", L"Failed to load ") \
X(DLL_REG_HR,          L"Регистрация вернула ошибку 0x", L"Registration returned error 0x") \
X(DLL_REGISTERED,      L"DLL зарегистрирована. Плитка появится на экране блокировки (Win+L).", L"DLL registered. The tile will appear on the lock screen (Win+L).") \
X(DLL_UNREGISTERED,    L"Регистрация снята.", L"Registration removed.") \
X(ERROR_SUFFIX,        L", ошибка ", L", error ") \
/* --- GUI --- */ \
X(GUI_TITLE,           L"Настройка входа по отпечатку", L"Fingerprint sign-in setup") \
X(GUI_ERROR_TITLE,     L"Ошибка", L"Error") \
X(GUI_ERROR_PREFIX,    L"ОШИБКА: ", L"ERROR: ") \
X(GUI_INTRO,           L"Порядок: 1) настроить устройство и пароль, 2) записать палец, 3) проверить, затем «Зарегистрировать DLL» и Win+L.", L"Order: 1) set up the device and password, 2) enroll a finger, 3) test, then \"Register DLL\" and Win+L.") \
X(GUI_MSA_DETECTED,    L"Обнаружен аккаунт Microsoft: имя и домен подставлены. Пароль нужен от аккаунта Microsoft, не PIN.", L"Microsoft account detected: name and domain filled in. Use the Microsoft account password, not the PIN.") \
X(GUI_ST_CFG_USER,     L"Конфигурация: пользователь ", L"Configuration: user ") \
X(GUI_ST_TILE_ON,      L", плитка включена", L", tile enabled") \
X(GUI_ST_TILE_OFF,     L", плитка ВЫКЛЮЧЕНА", L", tile DISABLED") \
X(GUI_ST_NOT_CFG,      L"Конфигурация: не настроено", L"Configuration: not set up") \
X(GUI_ST_DLL_REG,      L".  DLL зарегистрирована.", L".  DLL registered.") \
X(GUI_ST_DLL_NOT_REG,  L".  DLL НЕ зарегистрирована.", L".  DLL NOT registered.") \
X(GUI_PORTS_NONE,      L"COM-портов нет.", L"No COM ports.") \
X(GUI_PORTS,           L"COM-порты:", L"COM ports:") \
X(GUI_ST_DEVICE_ON,    L"\nУстройство на ", L"\nDevice on ") \
X(GUI_ST_KEYS,         L": ключи ", L": keys ") \
X(GUI_ST_KEYS_YES,     L"записаны", L"provisioned") \
X(GUI_ST_KEYS_NO,      L"НЕ записаны", L"NOT provisioned") \
X(GUI_ST_TEMPLATES,    L", отпечатков в сканере: ", L", fingerprints in the scanner: ") \
X(GUI_ST_NO_DEVICE,    L"\nУстройство не найдено. ", L"\nDevice not found. ") \
X(GUI_LANG_SAVED,      L"Язык сохранён в настройках; он также применяется к плитке на экране входа.", L"Language saved to the settings; it also applies to the sign-in tile.") \
/* --- CLI --- */ \
X(CLI_PW_PROMPT,       L"Пароль учётной записи Windows: ", L"Windows account password: ") \
X(CLI_PW_REPEAT,       L"Повторите пароль: ", L"Repeat password: ") \
X(CLI_PW_NEW,          L"Новый пароль Windows: ", L"New Windows password: ") \
X(CLI_NEED_USER,       L"Нужен --user", L"--user is required") \
X(CLI_NEED_ID,         L"Нужен --id N (1..199)", L"--id N (1..199) is required") \
X(CLI_ACCOUNT_WARN,    L"Предупреждение: учётная запись %ls не найдена через LookupAccountName. Для аккаунта Microsoft используйте --domain MicrosoftAccount --user почта.\n", L"Warning: account %ls was not found by LookupAccountName. For a Microsoft account use --domain MicrosoftAccount --user e-mail.\n") \
X(CLI_PLUG_DEVICE,     L"Подключите RP2040 и проверьте прошивку.", L"Connect the RP2040 and check the firmware.") \
X(CLI_CFG_SAVED_AT,    L"Конфигурация сохранена в HKLM\\%ls (доступ только SYSTEM и администраторам).\n", L"Configuration saved to HKLM\\%ls (readable only by SYSTEM and administrators).\n") \
X(CLI_TEMPLATES_TEST,  L"\nВ сканере %d отпечатков. Проверьте: zwsetup test\n", L"\nThe scanner holds %d fingerprints. Test with: zwsetup test\n") \
X(CLI_NO_TEMPLATES,    L"\nВ сканере нет отпечатков. Запишите палец: zwsetup enroll --id 1\n", L"\nThe scanner holds no fingerprints. Enroll one: zwsetup enroll --id 1\n") \
X(CLI_ERROR,           L"Ошибка: ", L"Error: ") \
X(CLI_PW_LEN,          L"Пароль успешно расшифрован (длина %u). Проверяю через LogonUser...\n", L"Password decrypted (length %u). Verifying with LogonUser...\n") \
X(CLI_STATUS_CFG,      L"Конфигурация: ", L"Configuration: ") \
X(CLI_STATUS_ALL_PORTS,L"Все COM-порты в системе:", L"All COM ports in the system:") \
X(CLI_NONE,            L" нет", L" none") \
X(CLI_PORTS_WITH_ID,   L"Из них с USB id %ls: %ls\n", L"Of them with USB id %ls: %ls\n") \
X(CLI_NO,              L"нет", L"none") \
X(CLI_PORT_HINT,       L"Подсказка: найдите выше строку своей платы (VID_2E8A для RP2040) и передайте её id:\n  zwsetup provision --user ИМЯ --usbid \"VID_xxxx&PID_xxxx\"   (или --port COMn)\n", L"Hint: find your board above (VID_2E8A for RP2040) and pass its id:\n  zwsetup provision --user NAME --usbid \"VID_xxxx&PID_xxxx\"   (or --port COMn)\n") \
X(CLI_DEVICE_ON,       L"Устройство на %ls: provisioned=%d, отпечатков=%d\n", L"Device on %ls: provisioned=%d, fingerprints=%d\n") \
X(CLI_DEVICE_SILENT,   L"Устройство не отвечает:\n", L"Device does not respond:\n") \
X(CLI_DLL_REG,         L"ZwCredProv.dll зарегистрирована.\n", L"ZwCredProv.dll is registered.\n") \
X(CLI_DLL_NOT_REG,     L"ZwCredProv.dll НЕ зарегистрирована (regsvr32 ZwCredProv.dll).\n", L"ZwCredProv.dll is NOT registered (regsvr32 ZwCredProv.dll).\n") \
X(CLI_UNINSTALLED,     L"Конфигурация удалена. Снимите регистрацию DLL: regsvr32 /u ZwCredProv.dll\n", L"Configuration removed. Unregister the DLL: regsvr32 /u ZwCredProv.dll\n") \
X(CLI_LANG_SET,        L"Язык: ", L"Language: ")

#define ZW_ENUM(id, ru, en) id,
enum class S { ZW_STRINGS(ZW_ENUM) COUNT };
#undef ZW_ENUM

Lang CurrentLang();
void SetLang(Lang l);
// "auto" | "ru" | "en" (case-insensitive); anything else = auto.
void SetLangFromSetting(const std::wstring& setting);
const wchar_t* T(S id);
inline std::wstring Ts(S id) { return T(id); }

} // namespace zw
