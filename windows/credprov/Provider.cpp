#include "Provider.h"
#include "helpers.h"
#include "guid.h"
#include <propkey.h>
#include <shlwapi.h>

using namespace zw;
const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* GetFieldDescriptors();

ZwProvider::ZwProvider() {
    std::wstring err;
    _cfgOk = LoadConfig(_cfg, &err);
    LogEnable(_cfg.debug);
    Log(L"Provider created, cfgOk=%d enabled=%d (%ls)", (int)_cfgOk, (int)_cfg.enabled, err.c_str());
}

ZwProvider::~ZwProvider() {
    if (_cred) { _cred->StopWorker(); _cred->Release(); }
    if (_pEvents) _pEvents->Release();
    Log(L"Provider destroyed");
}

IFACEMETHODIMP ZwProvider::QueryInterface(REFIID riid, void** ppv) {
    if (riid == IID_IUnknown || riid == IID_ICredentialProvider) *ppv = static_cast<ICredentialProvider*>(this);
    else if (riid == IID_ICredentialProviderSetUserArray) *ppv = static_cast<ICredentialProviderSetUserArray*>(this);
    else { *ppv = nullptr; return E_NOINTERFACE; }
    AddRef(); return S_OK;
}

IFACEMETHODIMP ZwProvider::SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD) {
    Log(L"SetUsageScenario %d", (int)cpus);
    switch (cpus) {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
        _cpus = cpus;
        if (_cfgOk && _cfg.enabled && !_cred) _cred = new ZwCredential(this, cpus, _cfg);
        return S_OK;
    case CPUS_CHANGE_PASSWORD:
    case CPUS_CREDUI:
    default:
        return E_NOTIMPL;
    }
}

IFACEMETHODIMP ZwProvider::SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*) { return E_NOTIMPL; }

IFACEMETHODIMP ZwProvider::Advise(ICredentialProviderEvents* pcpe, UINT_PTR upAdviseContext) {
    if (_pEvents) _pEvents->Release();
    _pEvents = pcpe; _pEvents->AddRef();
    _adviseContext = upAdviseContext;
    if (_cred && _userAllowed) _cred->StartWorker();
    return S_OK;
}

IFACEMETHODIMP ZwProvider::UnAdvise() {
    if (_cred) _cred->StopWorker();
    if (_pEvents) { _pEvents->Release(); _pEvents = nullptr; }
    _adviseContext = 0;
    return S_OK;
}

IFACEMETHODIMP ZwProvider::GetFieldDescriptorCount(DWORD* pdwCount) { *pdwCount = FI_NUM_FIELDS; return S_OK; }

IFACEMETHODIMP ZwProvider::GetFieldDescriptorAt(DWORD dwIndex, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd) {
    if (dwIndex >= FI_NUM_FIELDS || !ppcpfd) return E_INVALIDARG;
    return FieldDescriptorCoAllocCopy(GetFieldDescriptors()[dwIndex], ppcpfd);
}

IFACEMETHODIMP ZwProvider::GetCredentialCount(DWORD* pdwCount, DWORD* pdwDefault, BOOL* pbAutoLogonWithDefault) {
    *pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT; *pbAutoLogonWithDefault = FALSE;
    if (!_cred || !_userAllowed) { *pdwCount = 0; return S_OK; }
    *pdwCount = 1;
    if (_cred->IsMatched()) { *pdwDefault = 0; *pbAutoLogonWithDefault = TRUE; }
    Log(L"GetCredentialCount: count=1 autologon=%d", (int)*pbAutoLogonWithDefault);
    return S_OK;
}

IFACEMETHODIMP ZwProvider::GetCredentialAt(DWORD dwIndex, ICredentialProviderCredential** ppcpc) {
    if (dwIndex != 0 || !_cred || !ppcpc) return E_INVALIDARG;
    return _cred->QueryInterface(IID_PPV_ARGS(ppcpc));
}

// On the unlock screen the array holds only the locked user; on the logon screen, the listed users.
// If our configured account is not among them, hide the tile (unlock would fail anyway).
// For Microsoft accounts LookupAccountName cannot resolve "MicrosoftAccount\mail", so the SID is
// taken from the user array by matching the qualified user name instead.
IFACEMETHODIMP ZwProvider::SetUserArray(ICredentialProviderUserArray* users) {
    if (!_cred) return S_OK;
    DWORD count = 0;
    if (FAILED(users->GetCount(&count))) return S_OK;
    std::wstring want = _cred->UserSid();
    std::wstring wantName = _cred->QualifiedUser();
    bool found = false;
    std::wstring onlySid;
    for (DWORD i = 0; i < count && !found; i++) {
        ICredentialProviderUser* u = nullptr;
        if (FAILED(users->GetAt(i, &u))) continue;
        PWSTR sid = nullptr, qname = nullptr;
        if (SUCCEEDED(u->GetSid(&sid)) && sid) {
            if (count == 1) onlySid = sid;
            if (!want.empty() && _wcsicmp(sid, want.c_str()) == 0) found = true;
            else if (SUCCEEDED(u->GetStringValue(PKEY_Identity_QualifiedUserName, &qname)) && qname) {
                Log(L"SetUserArray: user[%lu] %ls sid=%ls", i, qname, sid);
                if (_wcsicmp(qname, wantName.c_str()) == 0) { found = true; _cred->SetUserSid(sid); }
                CoTaskMemFree(qname);
            }
            CoTaskMemFree(sid);
        }
        u->Release();
    }
    // Unlock screen with a single user whose SID we could not resolve: assume it is ours.
    if (!found && want.empty() && count == 1 && _cpus == CPUS_UNLOCK_WORKSTATION && !onlySid.empty()) {
        _cred->SetUserSid(onlySid); found = true;
        Log(L"SetUserArray: SID unresolved, bound to the only (locked) user");
    }
    _userAllowed = found || count == 0 || want.empty();
    Log(L"SetUserArray: %lu users, allowed=%d, sid=%ls", count, (int)_userAllowed, _cred->UserSid().c_str());
    return S_OK;
}

void ZwProvider::OnCredentialChanged() {
    if (_pEvents) _pEvents->CredentialsChanged(_adviseContext);
}
