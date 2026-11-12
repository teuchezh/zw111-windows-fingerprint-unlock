#pragma once
#include <windows.h>
#include <credentialprovider.h>
#include "Credential.h"

class ZwProvider : public ICredentialProvider, public ICredentialProviderSetUserArray {
public:
    ZwProvider();

    // IUnknown
    IFACEMETHODIMP_(ULONG) AddRef() override { return InterlockedIncrement(&_cRef); }
    IFACEMETHODIMP_(ULONG) Release() override { LONG c = InterlockedDecrement(&_cRef); if (!c) delete this; return c; }
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override;

    // ICredentialProvider
    IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags) override;
    IFACEMETHODIMP SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs) override;
    IFACEMETHODIMP Advise(ICredentialProviderEvents* pcpe, UINT_PTR upAdviseContext) override;
    IFACEMETHODIMP UnAdvise() override;
    IFACEMETHODIMP GetFieldDescriptorCount(DWORD* pdwCount) override;
    IFACEMETHODIMP GetFieldDescriptorAt(DWORD dwIndex, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd) override;
    IFACEMETHODIMP GetCredentialCount(DWORD* pdwCount, DWORD* pdwDefault, BOOL* pbAutoLogonWithDefault) override;
    IFACEMETHODIMP GetCredentialAt(DWORD dwIndex, ICredentialProviderCredential** ppcpc) override;

    // ICredentialProviderSetUserArray
    IFACEMETHODIMP SetUserArray(ICredentialProviderUserArray* users) override;

    // Called by the credential's worker thread.
    void OnCredentialChanged();

private:
    virtual ~ZwProvider();
    LONG _cRef = 1;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO _cpus = CPUS_INVALID;
    ZwCredential* _cred = nullptr;
    ICredentialProviderEvents* _pEvents = nullptr;
    UINT_PTR _adviseContext = 0;
    bool _userAllowed = true;      // configured user is present in the user array
    zw::Config _cfg;
    bool _cfgOk = false;
};
