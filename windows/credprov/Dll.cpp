#include <windows.h>
#include <initguid.h>
#include <unknwn.h>
#include <credentialprovider.h>
#include <string>
#include "guid.h"
#include "Provider.h"

static LONG g_cRef = 0;
static HINSTANCE g_hinst = nullptr;
void DllAddRef() { InterlockedIncrement(&g_cRef); }
void DllRelease() { InterlockedDecrement(&g_cRef); }

class ClassFactory : public IClassFactory {
public:
    ClassFactory() : _cRef(1) { DllAddRef(); }
    IFACEMETHODIMP_(ULONG) AddRef() { return InterlockedIncrement(&_cRef); }
    IFACEMETHODIMP_(ULONG) Release() { LONG c = InterlockedDecrement(&_cRef); if (!c) delete this; return c; }
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) {
        if (riid == IID_IUnknown || riid == IID_IClassFactory) { *ppv = static_cast<IClassFactory*>(this); AddRef(); return S_OK; }
        *ppv = nullptr; return E_NOINTERFACE;
    }
    IFACEMETHODIMP CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppv) {
        if (pUnkOuter) return CLASS_E_NOAGGREGATION;
        ZwProvider* p = new (std::nothrow) ZwProvider();
        if (!p) return E_OUTOFMEMORY;
        HRESULT hr = p->QueryInterface(riid, ppv);
        p->Release();
        return hr;
    }
    IFACEMETHODIMP LockServer(BOOL bLock) { if (bLock) DllAddRef(); else DllRelease(); return S_OK; }
private:
    virtual ~ClassFactory() { DllRelease(); }
    LONG _cRef;
};

extern "C" {

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) { g_hinst = hinst; DisableThreadLibraryCalls(hinst); }
    return TRUE;
}

HRESULT WINAPI DllCanUnloadNow() { return g_cRef > 0 ? S_FALSE : S_OK; }

HRESULT WINAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv) {
    *ppv = nullptr;
    if (rclsid != CLSID_ZwCredentialProvider) return CLASS_E_CLASSNOTAVAILABLE;
    ClassFactory* f = new (std::nothrow) ClassFactory();
    if (!f) return E_OUTOFMEMORY;
    HRESULT hr = f->QueryInterface(riid, ppv);
    f->Release();
    return hr;
}

static LONG SetKeyValue(HKEY root, const wchar_t* path, const wchar_t* name, const wchar_t* value) {
    HKEY k; LONG r = RegCreateKeyExW(root, path, 0, nullptr, 0, KEY_SET_VALUE | KEY_WOW64_64KEY, nullptr, &k, nullptr);
    if (r != ERROR_SUCCESS) return r;
    r = RegSetValueExW(k, name, 0, REG_SZ, (const BYTE*)value, (DWORD)((wcslen(value) + 1) * sizeof(wchar_t)));
    RegCloseKey(k);
    return r;
}

HRESULT WINAPI DllRegisterServer() {
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(g_hinst, path, MAX_PATH);
    std::wstring clsidKey = L"CLSID\\" ZW_CLSID_STRING;
    std::wstring inproc = clsidKey + L"\\InprocServer32";
    if (SetKeyValue(HKEY_CLASSES_ROOT, clsidKey.c_str(), nullptr, ZW_PROVIDER_NAME) != ERROR_SUCCESS) return E_ACCESSDENIED;
    if (SetKeyValue(HKEY_CLASSES_ROOT, inproc.c_str(), nullptr, path) != ERROR_SUCCESS) return E_ACCESSDENIED;
    if (SetKeyValue(HKEY_CLASSES_ROOT, inproc.c_str(), L"ThreadingModel", L"Apartment") != ERROR_SUCCESS) return E_ACCESSDENIED;
    std::wstring cp = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\" ZW_CLSID_STRING;
    if (SetKeyValue(HKEY_LOCAL_MACHINE, cp.c_str(), nullptr, ZW_PROVIDER_NAME) != ERROR_SUCCESS) return E_ACCESSDENIED;
    return S_OK;
}

HRESULT WINAPI DllUnregisterServer() {
    RegDeleteTreeW(HKEY_CLASSES_ROOT, L"CLSID\\" ZW_CLSID_STRING);
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\" ZW_CLSID_STRING);
    return S_OK;
}

} // extern "C"
