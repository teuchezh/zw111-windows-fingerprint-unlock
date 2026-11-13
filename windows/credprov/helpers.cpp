#define SECURITY_WIN32
#include "helpers.h"
#include <wincred.h>
#include <shlwapi.h>
#include <security.h>
#include <string.h>

static void InitLsaString(UNICODE_STRING* pus, PWSTR pwz) {
    size_t len = pwz ? wcslen(pwz) : 0;
    pus->Buffer = pwz;
    pus->Length = (USHORT)(len * sizeof(wchar_t));
    pus->MaximumLength = pus->Length;
}

HRESULT KerbInteractiveUnlockLogonInit(PWSTR pwzDomain, PWSTR pwzUsername, PWSTR pwzPassword,
                                       CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, KERB_INTERACTIVE_UNLOCK_LOGON* pkiul) {
    ZeroMemory(pkiul, sizeof(*pkiul));
    KERB_INTERACTIVE_LOGON* pkil = &pkiul->Logon;
    InitLsaString(&pkil->LogonDomainName, pwzDomain);
    InitLsaString(&pkil->UserName, pwzUsername);
    InitLsaString(&pkil->Password, pwzPassword);
    switch (cpus) {
    case CPUS_UNLOCK_WORKSTATION: pkil->MessageType = KerbWorkstationUnlockLogon; break;
    case CPUS_LOGON:
    case CPUS_CREDUI:             pkil->MessageType = KerbInteractiveLogon; break;
    default: return E_FAIL;
    }
    return S_OK;
}

// Packs the structure so that all string buffers follow it contiguously and Buffer fields
// hold byte offsets from the start of the block, as LSA expects.
HRESULT KerbInteractiveUnlockLogonPack(const KERB_INTERACTIVE_UNLOCK_LOGON& rkiulIn, BYTE** prgb, DWORD* pcb) {
    const KERB_INTERACTIVE_LOGON* pkilIn = &rkiulIn.Logon;
    DWORD cb = sizeof(rkiulIn) + pkilIn->LogonDomainName.Length + pkilIn->UserName.Length + pkilIn->Password.Length;
    KERB_INTERACTIVE_UNLOCK_LOGON* pkiulOut = (KERB_INTERACTIVE_UNLOCK_LOGON*)CoTaskMemAlloc(cb);
    if (!pkiulOut) return E_OUTOFMEMORY;
    ZeroMemory(pkiulOut, cb);
    pkiulOut->LogonId = rkiulIn.LogonId;
    KERB_INTERACTIVE_LOGON* pkilOut = &pkiulOut->Logon;
    pkilOut->MessageType = pkilIn->MessageType;
    BYTE* pbBuffer = (BYTE*)pkiulOut + sizeof(*pkiulOut);
    auto pack = [&](const UNICODE_STRING& in, UNICODE_STRING& out) {
        out.Length = in.Length; out.MaximumLength = in.MaximumLength;
        out.Buffer = (PWSTR)(pbBuffer - (BYTE*)pkiulOut);
        if (in.Length) memcpy(pbBuffer, in.Buffer, in.Length);
        pbBuffer += in.Length;
    };
    pack(pkilIn->LogonDomainName, pkilOut->LogonDomainName);
    pack(pkilIn->UserName, pkilOut->UserName);
    pack(pkilIn->Password, pkilOut->Password);
    *prgb = (BYTE*)pkiulOut; *pcb = cb;
    return S_OK;
}

HRESULT RetrieveNegotiateAuthPackage(ULONG* pulAuthPackage) { return RetrieveAuthPackage(NEGOSSP_NAME_A, pulAuthPackage); }

HRESULT RetrieveAuthPackage(const char* pkgName, ULONG* pulAuthPackage) {
    HANDLE hLsa;
    NTSTATUS st = LsaConnectUntrusted(&hLsa);
    if (st != 0) return HRESULT_FROM_NT(st);
    LSA_STRING name; char pkg[64]; strncpy(pkg, pkgName, sizeof(pkg) - 1); pkg[sizeof(pkg) - 1] = 0;
    name.Buffer = pkg; name.Length = (USHORT)strlen(pkg); name.MaximumLength = name.Length + 1;
    ULONG pkgId = 0;
    st = LsaLookupAuthenticationPackage(hLsa, &name, &pkgId);
    LsaDeregisterLogonProcess(hLsa);
    if (st != 0) return HRESULT_FROM_NT(st);
    *pulAuthPackage = pkgId;
    return S_OK;
}

static HRESULT ProtectAndCopyString(PCWSTR pwzToProtect, PWSTR* ppwzProtected) {
    *ppwzProtected = nullptr;
    DWORD cch = 0; CRED_PROTECTION_TYPE type;
    // CredProtect counts the terminating NUL.
    if (!CredProtectW(FALSE, (PWSTR)pwzToProtect, (DWORD)wcslen(pwzToProtect) + 1, nullptr, &cch, &type)
        && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        PWSTR out = (PWSTR)CoTaskMemAlloc(cch * sizeof(wchar_t));
        if (!out) return E_OUTOFMEMORY;
        if (CredProtectW(FALSE, (PWSTR)pwzToProtect, (DWORD)wcslen(pwzToProtect) + 1, out, &cch, &type)) {
            *ppwzProtected = out; return S_OK;
        }
        CoTaskMemFree(out);
    }
    return HRESULT_FROM_WIN32(GetLastError());
}

HRESULT ProtectIfNecessaryAndCopyPassword(PCWSTR pwzPassword, CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, PWSTR* ppwzProtectedPassword) {
    *ppwzProtectedPassword = nullptr;
    if (!pwzPassword || !*pwzPassword) return SHStrDupW(L"", ppwzProtectedPassword);
    CRED_PROTECTION_TYPE type;
    bool alreadyProtected = CredIsProtectedW((PWSTR)pwzPassword, &type) && type != CredUnprotected;
    if (alreadyProtected) return SHStrDupW(pwzPassword, ppwzProtectedPassword);
    if (cpus == CPUS_LOGON || cpus == CPUS_UNLOCK_WORKSTATION) {
        HRESULT hr = ProtectAndCopyString(pwzPassword, ppwzProtectedPassword);
        if (SUCCEEDED(hr)) return hr;
    }
    return SHStrDupW(pwzPassword, ppwzProtectedPassword);
}

HRESULT FieldDescriptorCoAllocCopy(const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& rcpfd, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd) {
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* p = (CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*)CoTaskMemAlloc(sizeof(*p));
    if (!p) return E_OUTOFMEMORY;
    p->dwFieldID = rcpfd.dwFieldID; p->cpft = rcpfd.cpft; p->guidFieldType = rcpfd.guidFieldType; p->pszLabel = nullptr;
    HRESULT hr = rcpfd.pszLabel ? SHStrDupW(rcpfd.pszLabel, &p->pszLabel) : S_OK;
    if (FAILED(hr)) { CoTaskMemFree(p); return hr; }
    *ppcpfd = p;
    return S_OK;
}

// The app icon (128x128, premultiplied alpha) as a 32bpp top-down DIB for the sign-in tile.
#include "tile_icon.h"
HBITMAP CreateTileBitmap() {
    const int N = ZW_TILE_ICON_SIZE;
    BITMAPINFO bi = {}; bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = N; bi.bmiHeader.biHeight = -N; bi.bmiHeader.biPlanes = 1; bi.bmiHeader.biBitCount = 32; bi.bmiHeader.biCompression = BI_RGB;
    void* bits = nullptr;
    HBITMAP hbm = CreateDIBSection(nullptr, &bi, DIB_RGB_COLORS, &bits, nullptr, 0);
    if (!hbm) return nullptr;
    memcpy(bits, kTileIconBgra, sizeof(kTileIconBgra));
    return hbm;
}
