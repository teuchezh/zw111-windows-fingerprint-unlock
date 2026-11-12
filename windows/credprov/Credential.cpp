#include "Credential.h"
#include "Provider.h"
#include "helpers.h"
#include "guid.h"
#include "../common/proto.h"
#include "../common/sha256.h"
#include <shlwapi.h>
#include <sddl.h>
#include <strsafe.h>

using namespace zw;

// Field GUIDs from credentialprovider.h (not present in every SDK)
static const GUID kCpfgLogo  = { 0x2d837775, 0xf6cd, 0x464e, { 0xa7, 0x45, 0x48, 0x2f, 0xd0, 0xb4, 0x74, 0x93 } };
static const GUID kCpfgLabel = { 0x286bbff3, 0xbad4, 0x438f, { 0xb0, 0x07, 0x79, 0xb7, 0x26, 0x7c, 0x3d, 0x48 } };

static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_fields[FI_NUM_FIELDS] = {
    { FI_TILEIMAGE, CPFT_TILE_IMAGE,    (PWSTR)L"Image",  kCpfgLogo },
    { FI_LABEL,     CPFT_LARGE_TEXT,    (PWSTR)L"Отпечаток пальца", kCpfgLabel },
    { FI_STATUS,    CPFT_SMALL_TEXT,    (PWSTR)L"Статус", GUID_NULL },
    { FI_SUBMIT,    CPFT_SUBMIT_BUTTON, (PWSTR)L"Войти",  GUID_NULL },
};
const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* GetFieldDescriptors() { return s_fields; }

ZwCredential::ZwCredential(ZwProvider* provider, CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, const Config& cfg)
    : _provider(provider), _cpus(cpus), _cfg(cfg) {
    _domain = EffectiveDomain(cfg);
    _status = L"Подключение к сканеру…";
    _hRestart = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    // Resolve the SID of the configured account so LogonUI can attach the tile to that user.
    std::wstring qualified = _domain + L"\\" + cfg.user;
    BYTE sidBuf[SECURITY_MAX_SID_SIZE]; DWORD cbSid = sizeof(sidBuf);
    wchar_t refDom[256]; DWORD cchDom = 256; SID_NAME_USE use;
    if (LookupAccountNameW(nullptr, qualified.c_str(), sidBuf, &cbSid, refDom, &cchDom, &use)) {
        LPWSTR s = nullptr;
        if (ConvertSidToStringSidW(sidBuf, &s)) { _sid = s; LocalFree(s); }
    }
    Log(L"Credential created: user=%ls domain=%ls sid=%ls cpus=%d", cfg.user.c_str(), _domain.c_str(), _sid.c_str(), (int)cpus);
}

ZwCredential::~ZwCredential() {
    StopWorker();
    if (_hRestart) CloseHandle(_hRestart);
    if (!_password.empty()) SecureZeroMemory(&_password[0], _password.size() * sizeof(wchar_t));
    if (_pCredEvents) _pCredEvents->Release();
}

IFACEMETHODIMP ZwCredential::QueryInterface(REFIID riid, void** ppv) {
    if (riid == IID_IUnknown || riid == IID_ICredentialProviderCredential) *ppv = static_cast<ICredentialProviderCredential*>(this);
    else if (riid == IID_ICredentialProviderCredential2) *ppv = static_cast<ICredentialProviderCredential2*>(this);
    else { *ppv = nullptr; return E_NOINTERFACE; }
    AddRef(); return S_OK;
}

IFACEMETHODIMP ZwCredential::Advise(ICredentialProviderCredentialEvents* pcpce) {
    if (_pCredEvents) _pCredEvents->Release();
    _pCredEvents = pcpce; if (_pCredEvents) _pCredEvents->AddRef();
    return S_OK;
}
IFACEMETHODIMP ZwCredential::UnAdvise() {
    if (_pCredEvents) _pCredEvents->Release();
    _pCredEvents = nullptr;
    return S_OK;
}

IFACEMETHODIMP ZwCredential::SetSelected(BOOL* pbAutoLogon) {
    std::lock_guard<std::mutex> g(_mtx);
    *pbAutoLogon = _matched ? TRUE : FALSE;
    return S_OK;
}
IFACEMETHODIMP ZwCredential::SetDeselected() { return S_OK; }

IFACEMETHODIMP ZwCredential::GetFieldState(DWORD id, CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis) {
    if (id >= FI_NUM_FIELDS) return E_INVALIDARG;
    *pcpfis = CPFIS_NONE;
    *pcpfs = (id == FI_TILEIMAGE || id == FI_LABEL) ? CPFS_DISPLAY_IN_BOTH : CPFS_DISPLAY_IN_SELECTED_TILE;
    return S_OK;
}

IFACEMETHODIMP ZwCredential::GetStringValue(DWORD id, PWSTR* ppwsz) {
    switch (id) {
    case FI_LABEL:  return SHStrDupW(L"Отпечаток пальца", ppwsz);
    case FI_STATUS: { std::lock_guard<std::mutex> g(_mtx); return SHStrDupW(_status.c_str(), ppwsz); }
    case FI_SUBMIT: return SHStrDupW(L"Войти", ppwsz);
    default: return E_INVALIDARG;
    }
}

IFACEMETHODIMP ZwCredential::GetBitmapValue(DWORD id, HBITMAP* phbmp) {
    if (id != FI_TILEIMAGE) return E_INVALIDARG;
    *phbmp = CreateTileBitmap();
    return *phbmp ? S_OK : HRESULT_FROM_WIN32(GetLastError());
}

IFACEMETHODIMP ZwCredential::GetSubmitButtonValue(DWORD id, DWORD* pdwAdjacentTo) {
    if (id != FI_SUBMIT) return E_INVALIDARG;
    *pdwAdjacentTo = FI_STATUS;
    return S_OK;
}

IFACEMETHODIMP ZwCredential::GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
                                              CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
                                              PWSTR* ppwszOptionalStatusText, CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon) {
    *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    *ppwszOptionalStatusText = nullptr; *pcpsiOptionalStatusIcon = CPSI_NONE;
    ZeroMemory(pcpcs, sizeof(*pcpcs));

    std::wstring password;
    {
        std::lock_guard<std::mutex> g(_mtx);
        if (!_matched) {
            SHStrDupW(L"Приложите палец к сканеру", ppwszOptionalStatusText);
            *pcpsiOptionalStatusIcon = CPSI_WARNING;
            return S_FALSE;
        }
        password = _password;
        SecureZeroMemory(&_password[0], _password.size() * sizeof(wchar_t));
        _password.clear();
    }
    Log(L"GetSerialization: building logon for %ls\\%ls", _domain.c_str(), _cfg.user.c_str());

    PWSTR pwzProtected = nullptr;
    HRESULT hr = ProtectIfNecessaryAndCopyPassword(password.c_str(), _cpus, &pwzProtected);
    SecureZeroMemory(&password[0], password.size() * sizeof(wchar_t));
    if (FAILED(hr)) return hr;

    KERB_INTERACTIVE_UNLOCK_LOGON kiul;
    std::wstring dom = _domain, usr = _cfg.user;
    hr = KerbInteractiveUnlockLogonInit(&dom[0], &usr[0], pwzProtected, _cpus, &kiul);
    if (SUCCEEDED(hr)) hr = KerbInteractiveUnlockLogonPack(kiul, &pcpcs->rgbSerialization, &pcpcs->cbSerialization);
    if (SUCCEEDED(hr)) {
        ULONG pkg = 0;
        hr = RetrieveNegotiateAuthPackage(&pkg);
        if (SUCCEEDED(hr)) {
            pcpcs->ulAuthenticationPackage = pkg;
            pcpcs->clsidCredentialProvider = CLSID_ZwCredentialProvider;
            *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
        }
    }
    if (pwzProtected) { SecureZeroMemory(pwzProtected, wcslen(pwzProtected) * sizeof(wchar_t)); CoTaskMemFree(pwzProtected); }
    Log(L"GetSerialization: hr=0x%08x", hr);
    return hr;
}

IFACEMETHODIMP ZwCredential::ReportResult(NTSTATUS ntsStatus, NTSTATUS ntsSubstatus, PWSTR* ppwszOptionalStatusText,
                                          CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon) {
    *ppwszOptionalStatusText = nullptr; *pcpsiOptionalStatusIcon = CPSI_NONE;
    Log(L"ReportResult: status=0x%08x sub=0x%08x", ntsStatus, ntsSubstatus);
    {
        std::lock_guard<std::mutex> g(_mtx);
        _matched = false;
    }
    if (ntsStatus != 0) {
        wchar_t msg[160];
        StringCchPrintfW(msg, 160, L"Вход не выполнен (0x%08X). Пароль в хранилище устарел? Запустите zwsetup set-password.", (unsigned)ntsStatus);
        SHStrDupW(msg, ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        SetStatus(L"Приложите палец к сканеру", false);
        if (_hRestart) SetEvent(_hRestart);   // run another handshake
    }
    return S_OK;
}

IFACEMETHODIMP ZwCredential::GetUserSid(PWSTR* ppszSid) {
    if (_sid.empty()) { *ppszSid = nullptr; return S_FALSE; }   // shown under "Other user"
    return SHStrDupW(_sid.c_str(), ppszSid);
}

bool ZwCredential::IsMatched() { std::lock_guard<std::mutex> g(_mtx); return _matched; }

void ZwCredential::SetStatus(const std::wstring& s, bool notify) {
    bool changed;
    { std::lock_guard<std::mutex> g(_mtx); changed = (_status != s); _status = s; }
    if (changed && notify) NotifyProvider();
}

void ZwCredential::NotifyProvider() { if (_provider) _provider->OnCredentialChanged(); }

void ZwCredential::StartWorker() {
    if (_worker.joinable()) return;
    _stop = false; _cancelAuth = false;
    _worker = std::thread([this] { WorkerMain(); });
}

void ZwCredential::StopWorker() {
    _stop = true; _cancelAuth = true;
    if (_hRestart) SetEvent(_hRestart);
    if (_worker.joinable()) _worker.join();
}

// Worker: find the device, run handshakes until a finger matches, hand the password to GetSerialization.
void ZwCredential::WorkerMain() {
    Log(L"worker start");
    Secrets secrets;
    std::wstring err;
    if (!UnprotectSecrets(_cfg.blob, secrets, &err)) {
        Log(L"UnprotectSecrets failed: %ls", err.c_str());
        SetStatus(L"Ошибка конфигурации: " + err, true);
        return;
    }
    SerialPort port;
    std::wstring portName;
    int backoffMs = 1000;
    while (!_stop) {
        if (!port.IsOpen()) {
            if (!OpenDevice(port, _cfg.port, _cfg.usbId, &portName)) {
                SetStatus(L"Сканер не подключён", true);
                for (int i = 0; i < backoffMs / 100 && !_stop; i++) Sleep(100);
                if (backoffMs < 3000) backoffMs += 500;
                continue;
            }
            backoffMs = 1000;
            Log(L"device opened on %ls", portName.c_str());
        }
        uint8_t kdev[32]; int fingerId = 0; std::string perr;
        _cancelAuth = false;
        AuthResult r = RunAuth(port, secrets.kauth, _cancelAuth, kdev, fingerId, &perr,
            [this](const std::string& ev) {
                if (ev == "WAIT") SetStatus(L"Приложите палец к сканеру", true);
                else if (ev == "NOMATCH") SetStatus(L"Палец не распознан, попробуйте ещё раз", true);
            });
        if (_stop) break;
        switch (r) {
        case AuthResult::Match: {
            Log(L"MATCH finger=%d", fingerId);
            if (_cfg.fingerId != 0 && (DWORD)fingerId != _cfg.fingerId) {
                SecureZeroMemory(kdev, 32);
                SetStatus(L"Этот палец не разрешён для входа", true);
                Sleep(1500);
                continue;
            }
            std::wstring pw;
            bool ok = OpenPassword(secrets, kdev, pw);
            SecureZeroMemory(kdev, 32);
            if (!ok) {
                Log(L"OpenPassword failed (device/PC key mismatch)");
                SetStatus(L"Устройство не соответствует этому ПК. Запустите zwsetup provision.", true);
                Sleep(3000);
                continue;
            }
            {
                std::lock_guard<std::mutex> g(_mtx);
                _password = pw; _matched = true; _status = L"Отпечаток распознан, выполняется вход…";
            }
            SecureZeroMemory(&pw[0], pw.size() * sizeof(wchar_t));
            NotifyProvider();     // LogonUI re-enumerates, sees auto-logon and calls GetSerialization
            // Wait for the logon attempt to finish (ReportResult) or for a timeout, keeping the port open.
            DWORD w = WaitForSingleObject(_hRestart, 60000);
            if (w == WAIT_TIMEOUT) {
                std::lock_guard<std::mutex> g(_mtx);
                if (_matched) {      // nobody consumed it: drop the password
                    _matched = false;
                    if (!_password.empty()) SecureZeroMemory(&_password[0], _password.size() * sizeof(wchar_t));
                    _password.clear();
                }
            }
            break;
        }
        case AuthResult::NoDevice:
            Log(L"device lost: %ls", A2W(perr).c_str());
            port.Close();
            SetStatus(L"Сканер отключён", true);
            break;
        case AuthResult::AuthFailed:
            SetStatus(L"Устройство не принимает этот ПК (ключ K_auth). Запустите zwsetup provision.", true);
            for (int i = 0; i < 50 && !_stop; i++) Sleep(100);
            break;
        case AuthResult::NotProvisioned:
            SetStatus(L"Устройство не настроено. Запустите zwsetup provision.", true);
            for (int i = 0; i < 50 && !_stop; i++) Sleep(100);
            break;
        case AuthResult::Timeout:
            break;   // device stopped waiting; immediately start a new handshake
        case AuthResult::Cancelled:
            break;
        case AuthResult::Error:
            Log(L"protocol error: %ls", A2W(perr).c_str());
            Sleep(1000);
            break;
        }
    }
    if (port.IsOpen()) { port.WriteLine("CANCEL"); port.Close(); }
    Log(L"worker stop");
}
