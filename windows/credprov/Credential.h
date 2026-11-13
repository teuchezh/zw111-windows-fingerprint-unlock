#pragma once
#include <windows.h>
#include <credentialprovider.h>
#include <string>
#include <mutex>
#include <atomic>
#include <thread>
#include "../common/config.h"

// Undocumented extension used by Windows 11 LogonUI: hands the tile image over as a PNG buffer, which keeps
// its alpha channel (the HBITMAP from GetBitmapValue is drawn on a black square). Same ABI as Lithnet's
// ICredentialProviderCredential3 {64A5010E-4363-41F8-9738-19045C20DABC}.
struct ICredentialProviderCredential3 : public ICredentialProviderCredential2 {
    virtual HRESULT STDMETHODCALLTYPE GetBitmapBufferValue(DWORD dwFieldID, DWORD* pImageBufferSize, BYTE** ppImageBuffer) = 0;
};
extern const IID IID_ICredentialProviderCredential3_ZW;

enum FIELD_ID { FI_TILEIMAGE = 0, FI_LABEL = 1, FI_STATUS = 2, FI_SUBMIT = 3, FI_NUM_FIELDS = 4 };

class ZwProvider;

// One tile: "Fingerprint". Owns the worker thread that talks to the device.
class ZwCredential : public ICredentialProviderCredential3 {
public:
    // sidOverride: SID reported by the broker service (CredUI scenario), empty otherwise.
    ZwCredential(ZwProvider* provider, CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, const zw::Config& cfg, const std::wstring& sidOverride = L"");

    // IUnknown
    IFACEMETHODIMP_(ULONG) AddRef() override { return InterlockedIncrement(&_cRef); }
    IFACEMETHODIMP_(ULONG) Release() override { LONG c = InterlockedDecrement(&_cRef); if (!c) delete this; return c; }
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override;

    // ICredentialProviderCredential
    IFACEMETHODIMP Advise(ICredentialProviderCredentialEvents* pcpce) override;
    IFACEMETHODIMP UnAdvise() override;
    IFACEMETHODIMP SetSelected(BOOL* pbAutoLogon) override;
    IFACEMETHODIMP SetDeselected() override;
    IFACEMETHODIMP GetFieldState(DWORD dwFieldID, CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis) override;
    IFACEMETHODIMP GetStringValue(DWORD dwFieldID, PWSTR* ppwsz) override;
    IFACEMETHODIMP GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp) override;
    IFACEMETHODIMP GetCheckboxValue(DWORD, BOOL*, PWSTR*) override { return E_NOTIMPL; }
    IFACEMETHODIMP GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo) override;
    IFACEMETHODIMP GetComboBoxValueCount(DWORD, DWORD*, DWORD*) override { return E_NOTIMPL; }
    IFACEMETHODIMP GetComboBoxValueAt(DWORD, DWORD, PWSTR*) override { return E_NOTIMPL; }
    IFACEMETHODIMP SetStringValue(DWORD, PCWSTR) override { return E_NOTIMPL; }
    IFACEMETHODIMP SetCheckboxValue(DWORD, BOOL) override { return E_NOTIMPL; }
    IFACEMETHODIMP SetComboBoxSelectedValue(DWORD, DWORD) override { return E_NOTIMPL; }
    IFACEMETHODIMP CommandLinkClicked(DWORD) override { return E_NOTIMPL; }
    IFACEMETHODIMP GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
                                    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
                                    PWSTR* ppwszOptionalStatusText, CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon) override;
    IFACEMETHODIMP ReportResult(NTSTATUS ntsStatus, NTSTATUS ntsSubstatus, PWSTR* ppwszOptionalStatusText,
                                CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon) override;
    // ICredentialProviderCredential2
    IFACEMETHODIMP GetUserSid(PWSTR* ppszSid) override;
    // ICredentialProviderCredential3
    IFACEMETHODIMP GetBitmapBufferValue(DWORD dwFieldID, DWORD* pImageBufferSize, BYTE** ppImageBuffer) override;

    // Called by the provider.
    void StartWorker();
    void StopWorker();
    bool IsMatched();
    const std::wstring& UserSid() const { return _sid; }
    void SetUserSid(const std::wstring& sid) { _sid = sid; }
    std::wstring QualifiedUser() const { return _domain + L"\\" + _cfg.user; }

private:
    virtual ~ZwCredential();
    void WorkerMain();
    void BrokerWorker();     // CredUI: the SYSTEM service talks to the device for us
    void SetStatus(const std::wstring& s, bool notify);
    void NotifyProvider();

    LONG _cRef = 1;
    ZwProvider* _provider;                         // weak
    CREDENTIAL_PROVIDER_USAGE_SCENARIO _cpus;
    ICredentialProviderCredentialEvents* _pCredEvents = nullptr;
    zw::Config _cfg;
    std::wstring _domain, _sid;

    std::mutex _mtx;
    std::wstring _status;
    std::wstring _password;                        // decrypted, only between MATCH and GetSerialization
    bool _matched = false;
    bool _hadError = false;

    std::thread _worker;
    std::atomic<bool> _stop{false};
    std::atomic<bool> _cancelAuth{false};
    HANDLE _hRestart = nullptr;                    // signalled to run another handshake after a logon attempt
};
