#include "Credential.h"
#include "Provider.h"
#include "helpers.h"
#include "guid.h"
#include "../common/proto.h"
#include "../common/sha256.h"
#include "../common/i18n.h"
#include "../common/broker.h"
#include <shlwapi.h>
#include <sddl.h>
#include <strsafe.h>

using namespace zw;

const IID IID_ICredentialProviderCredential3_ZW = { 0x64a5010e, 0x4363, 0x41f8, { 0x97, 0x38, 0x19, 0x04, 0x5c, 0x20, 0xda, 0xbc } };

// Field GUIDs from credentialprovider.h (not present in every SDK)
static const GUID kCpfgLogo  = { 0x2d837775, 0xf6cd, 0x464e, { 0xa7, 0x45, 0x48, 0x2f, 0xd0, 0xb4, 0x74, 0x93 } };
static const GUID kCpfgLabel = { 0x286bbff3, 0xbad4, 0x438f, { 0xb0, 0x07, 0x79, 0xb7, 0x26, 0x7c, 0x3d, 0x48 } };

static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_fields[FI_NUM_FIELDS] = {
    { FI_TILEIMAGE, CPFT_TILE_IMAGE,    (PWSTR)L"Image",  kCpfgLogo },
    { FI_LABEL,     CPFT_LARGE_TEXT,    (PWSTR)L"Fingerprint", kCpfgLabel },
    { FI_STATUS,    CPFT_SMALL_TEXT,    (PWSTR)L"Status", GUID_NULL },
    { FI_SUBMIT,    CPFT_SUBMIT_BUTTON, (PWSTR)L"Sign in", GUID_NULL },
};
const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* GetFieldDescriptors() { return s_fields; }

ZwCredential::ZwCredential(ZwProvider* provider, CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, const Config& cfg, const std::wstring& sidOverride)
    : _provider(provider), _cpus(cpus), _cfg(cfg) {
    _domain = EffectiveDomain(cfg);
    _status = T(S::CP_CONNECTING);
    _hRestart = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    // Resolve the SID of the configured account so LogonUI can attach the tile to that user.
    std::wstring qualified = _domain + L"\\" + cfg.user;
    BYTE sidBuf[SECURITY_MAX_SID_SIZE]; DWORD cbSid = sizeof(sidBuf);
    wchar_t refDom[256]; DWORD cchDom = 256; SID_NAME_USE use;
    if (!sidOverride.empty()) _sid = sidOverride;
    else if (!cfg.userSid.empty()) _sid = cfg.userSid;
    else if (LookupAccountNameW(nullptr, qualified.c_str(), sidBuf, &cbSid, refDom, &cchDom, &use)) {
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
    else if (riid == IID_ICredentialProviderCredential3_ZW) *ppv = static_cast<ICredentialProviderCredential3*>(this);
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
    case FI_LABEL:  return SHStrDupW(T(S::CP_LABEL), ppwsz);
    case FI_STATUS: { std::lock_guard<std::mutex> g(_mtx); return SHStrDupW(_status.c_str(), ppwsz); }
    case FI_SUBMIT: return SHStrDupW(T(S::CP_SUBMIT), ppwsz);
    default: return E_INVALIDARG;
    }
}

IFACEMETHODIMP ZwCredential::GetBitmapValue(DWORD id, HBITMAP* phbmp) {
    if (id != FI_TILEIMAGE) return E_INVALIDARG;
    *phbmp = CreateTileBitmap();
    return *phbmp ? S_OK : HRESULT_FROM_WIN32(GetLastError());
}

#include "tile_icon.h"
IFACEMETHODIMP ZwCredential::GetBitmapBufferValue(DWORD dwFieldID, DWORD* pImageBufferSize, BYTE** ppImageBuffer) {
    if (!pImageBufferSize || !ppImageBuffer) return E_POINTER;
    *pImageBufferSize = 0; *ppImageBuffer = nullptr;
    if (dwFieldID != FI_TILEIMAGE) return E_INVALIDARG;
    BYTE* buf = (BYTE*)CoTaskMemAlloc(sizeof(kTilePng));
    if (!buf) return E_OUTOFMEMORY;
    memcpy(buf, kTilePng, sizeof(kTilePng));
    *ppImageBuffer = buf; *pImageBufferSize = sizeof(kTilePng);
    Log(L"GetBitmapBufferValue: %u bytes", (unsigned)sizeof(kTilePng));
    return S_OK;
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
            SHStrDupW(T(S::CP_TOUCH), ppwszOptionalStatusText);
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
        ULONG pkg = _authPackage;
        hr = pkg ? S_OK : RetrieveNegotiateAuthPackage(&pkg);
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
    // Leave a note for ZwSetup: a rejected logon usually means the Windows password changed.
    HKEY k;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kRegPath, 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &k) == ERROR_SUCCESS) {
        if (ntsStatus == 0) { RegDeleteValueW(k, L"LastLogonError"); RegDeleteValueW(k, L"LastLogonErrorTime"); }
        else {
            DWORD st = (DWORD)ntsStatus; FILETIME ft; GetSystemTimeAsFileTime(&ft);
            ULONGLONG t = ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
            RegSetValueExW(k, L"LastLogonError", 0, REG_DWORD, (const BYTE*)&st, sizeof(st));
            RegSetValueExW(k, L"LastLogonErrorTime", 0, REG_QWORD, (const BYTE*)&t, sizeof(t));
        }
        RegCloseKey(k);
    }
    {
        std::lock_guard<std::mutex> g(_mtx);
        _matched = false;
    }
    if (ntsStatus != 0) {
        wchar_t msg[200];
        if ((unsigned)ntsStatus == 0xC000006Du)
            StringCchPrintfW(msg, 200, L"%ls", T(S::CP_LOGON_BAD_CRED));
        else
            StringCchPrintfW(msg, 200, T(S::CP_LOGON_FAILED_FMT), (unsigned)ntsStatus);
        SHStrDupW(msg, ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        SetStatus(T(S::CP_TOUCH), false);
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
void ZwCredential::BrokerWorker() {
    Log(L"broker worker start");
    while (!_stop) {
        std::wstring pw; std::string err;
        _cancelAuth = false;
        BrokerResult r = BrokerAuthenticate(_cancelAuth, pw, err, [this](const std::string& ev) {
            if (ev == "WAIT" || ev == "READY") SetStatus(T(S::CP_TOUCH), true);
            else if (ev == "NOMATCH") SetStatus(T(S::CP_NOMATCH), true);
            else if (ev.compare(0, 7, "LOCKED ") == 0) {
                wchar_t msg[160];
                StringCchPrintfW(msg, 160, T(S::CP_LOCKED_FMT), (unsigned)atoi(ev.c_str() + 7));
                SetStatus(msg, true);
            }
        });
        if (_stop) { if (!pw.empty()) SecureZeroMemory(&pw[0], pw.size() * sizeof(wchar_t)); break; }
        Log(L"broker result %d (%S)", (int)r, err.c_str());
        switch (r) {
        case BrokerResult::Password:
            {
                std::lock_guard<std::mutex> g(_mtx);
                _password = pw; _matched = true; _status = T(S::CP_MATCHED);
            }
            SecureZeroMemory(&pw[0], pw.size() * sizeof(wchar_t));
            NotifyProvider();
            // CredUI collects the credential with GetSerialization; wait a while before offering another round.
            if (WaitForSingleObject(_hRestart, 60000) == WAIT_TIMEOUT) {
                std::lock_guard<std::mutex> g(_mtx);
                if (_matched) { _matched = false; if (!_password.empty()) SecureZeroMemory(&_password[0], _password.size() * sizeof(wchar_t)); _password.clear(); }
            }
            break;
        case BrokerResult::Disabled:
        case BrokerResult::Refused:
            SetStatus(T(S::CP_SVC_REFUSED), true);
            return;                                   // nothing will change while this prompt is open
        case BrokerResult::NoDevice:
            SetStatus(T(S::CP_NO_DEVICE), true);
            for (int i = 0; i < 30 && !_stop; i++) Sleep(100);
            break;
        case BrokerResult::Timeout:
        case BrokerResult::Cancelled:
            break;
        case BrokerResult::Error:
            if (err.compare(0, 6, "FINGER") == 0) SetStatus(T(S::CP_FINGER_DENIED2), true);
            else if (err == "service not running") SetStatus(T(S::CP_SVC_DOWN), true);
            for (int i = 0; i < 50 && !_stop; i++) Sleep(100);
            break;
        }
    }
    Log(L"broker worker stop");
}

void ZwCredential::WorkerMain() {
    if (_cpus == CPUS_CREDUI) { BrokerWorker(); return; }
    Log(L"worker start");
    Secrets secrets;
    std::wstring err;
    if (!UnprotectSecrets(_cfg.blob, secrets, &err)) {
        Log(L"UnprotectSecrets failed: %ls", err.c_str());
        SetStatus(Ts(S::CP_CFG_ERROR) + err, true);
        return;
    }
    SerialPort port;
    std::wstring portName;
    int backoffMs = 1000;
    while (!_stop) {
        if (!port.IsOpen()) {
            if (!OpenDevice(port, _cfg.port, _cfg.usbId, &portName)) {
                SetStatus(T(S::CP_NO_DEVICE), true);
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
                if (ev == "WAIT") SetStatus(T(S::CP_TOUCH), true);
                else if (ev == "NOMATCH") SetStatus(T(S::CP_NOMATCH), true);
                else if (ev == "READY") SetStatus(T(S::CP_TOUCH), true);
                else if (ev.compare(0, 7, "LOCKED ") == 0) {
                    wchar_t msg[160];
                    StringCchPrintfW(msg, 160, T(S::CP_LOCKED_FMT), (unsigned)atoi(ev.c_str() + 7));
                    SetStatus(msg, true);
                }
            });
        if (_stop) break;
        switch (r) {
        case AuthResult::Match: {
            Log(L"MATCH finger=%d", fingerId);
            if (_cfg.fingerId != 0 && (DWORD)fingerId != _cfg.fingerId) {
                SecureZeroMemory(kdev, 32);
                SetStatus(T(S::CP_FINGER_DENIED), true);
                Sleep(1500);
                continue;
            }
            std::wstring pw;
            bool ok = OpenPassword(secrets, kdev, pw);
            SecureZeroMemory(kdev, 32);
            if (!ok) {
                Log(L"OpenPassword failed (device/PC key mismatch)");
                SetStatus(T(S::CP_KEY_MISMATCH), true);
                Sleep(3000);
                continue;
            }
            {
                std::lock_guard<std::mutex> g(_mtx);
                _password = pw; _matched = true; _status = T(S::CP_MATCHED);
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
            SetStatus(T(S::CP_DEVICE_LOST), true);
            break;
        case AuthResult::AuthFailed:
            SetStatus(T(S::CP_AUTH_FAILED), true);
            for (int i = 0; i < 50 && !_stop; i++) Sleep(100);
            break;
        case AuthResult::NotProvisioned:
            SetStatus(T(S::CP_NOT_PROVISIONED), true);
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
