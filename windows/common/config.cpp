#include "config.h"
#include "sha256.h"
#include <bcrypt.h>
#include <dpapi.h>
#include <sddl.h>
#include <shlobj.h>
#include <stdio.h>
#include <stdarg.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

namespace zw {

const wchar_t* const kRegPath = L"SOFTWARE\\ZwCredProv";
static const uint32_t kBlobMagic = 0x3153575A; // "ZWS1"

Secrets::~Secrets() {
    SecureZeroMemory(kpc, sizeof(kpc)); SecureZeroMemory(kauth, sizeof(kauth));
    if (!ct.empty()) SecureZeroMemory(ct.data(), ct.size());
}

std::wstring A2W(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &w[0], n);
    return w;
}

// ---------- logging ----------
static bool g_logOn = false;
void LogEnable(bool on) { g_logOn = on; }
void Log(const wchar_t* fmt, ...) {
    if (!g_logOn) return;
    wchar_t dir[MAX_PATH];
    if (FAILED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, dir))) return;
    std::wstring path = std::wstring(dir) + L"\\ZwCredProv";
    CreateDirectoryW(path.c_str(), nullptr);
    path += L"\\zwcredprov.log";
    FILE* f = _wfopen(path.c_str(), L"a, ccs=UTF-8");
    if (!f) return;
    SYSTEMTIME st; GetLocalTime(&st);
    fwprintf(f, L"%04d-%02d-%02d %02d:%02d:%02d.%03d [%lu] ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, GetCurrentThreadId());
    va_list ap; va_start(ap, fmt); vfwprintf(f, fmt, ap); va_end(ap);
    fwprintf(f, L"\n");
    fclose(f);
}

// ---------- registry ----------
static bool RegStr(HKEY k, const wchar_t* name, std::wstring& out) {
    wchar_t buf[512]; DWORD cb = sizeof(buf) - 2, t = 0;
    if (RegQueryValueExW(k, name, nullptr, &t, (LPBYTE)buf, &cb) != ERROR_SUCCESS || t != REG_SZ) return false;
    buf[cb / 2] = 0; out = buf; return true;
}
static bool RegDword(HKEY k, const wchar_t* name, DWORD& out) {
    DWORD v = 0, cb = sizeof(v), t = 0;
    if (RegQueryValueExW(k, name, nullptr, &t, (LPBYTE)&v, &cb) != ERROR_SUCCESS || t != REG_DWORD) return false;
    out = v; return true;
}

bool LoadConfig(Config& cfg, std::wstring* err) {
    HKEY k;
    LONG r = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kRegPath, 0, KEY_READ | KEY_WOW64_64KEY, &k);
    if (r != ERROR_SUCCESS) { if (err) *err = L"Ключ реестра HKLM\\" + std::wstring(kRegPath) + L" не найден. Выполните zwsetup provision."; return false; }
    std::wstring s; DWORD d;
    if (RegStr(k, L"Port", s)) cfg.port = s;
    if (RegStr(k, L"UsbId", s)) cfg.usbId = s;
    if (RegStr(k, L"User", s)) cfg.user = s;
    if (RegStr(k, L"Domain", s)) cfg.domain = s;
    if (RegDword(k, L"FingerId", d)) cfg.fingerId = d;
    if (RegDword(k, L"Enabled", d)) cfg.enabled = d != 0;
    if (RegDword(k, L"Debug", d)) cfg.debug = d != 0;
    DWORD cb = 0, t = 0;
    if (RegQueryValueExW(k, L"Blob", nullptr, &t, nullptr, &cb) == ERROR_SUCCESS && t == REG_BINARY && cb > 0) {
        cfg.blob.resize(cb);
        if (RegQueryValueExW(k, L"Blob", nullptr, &t, cfg.blob.data(), &cb) != ERROR_SUCCESS) cfg.blob.clear();
    }
    RegCloseKey(k);
    if (cfg.user.empty() || cfg.blob.empty()) { if (err) *err = L"Конфигурация неполная (нет User или Blob)."; return false; }
    return true;
}

bool SaveConfig(const Config& cfg, std::wstring* err) {
    // Only SYSTEM and Administrators may read the key: the DPAPI blob is machine-scoped,
    // so anyone who can read it could decrypt K_pc/K_auth.
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:PAI(A;OICI;KA;;;SY)(A;OICI;KA;;;BA)", SDDL_REVISION_1, &sd, nullptr)) {
        if (err) *err = L"ConvertStringSecurityDescriptor failed";
        return false;
    }
    SECURITY_ATTRIBUTES sa = { sizeof(sa), sd, FALSE };
    HKEY k; DWORD disp;
    LONG r = RegCreateKeyExW(HKEY_LOCAL_MACHINE, kRegPath, 0, nullptr, 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, &sa, &k, &disp);
    LocalFree(sd);
    if (r != ERROR_SUCCESS) { if (err) *err = L"RegCreateKeyEx failed (нужны права администратора)"; return false; }
    auto setStr = [&](const wchar_t* n, const std::wstring& v) { RegSetValueExW(k, n, 0, REG_SZ, (const BYTE*)v.c_str(), (DWORD)((v.size() + 1) * 2)); };
    auto setDw  = [&](const wchar_t* n, DWORD v) { RegSetValueExW(k, n, 0, REG_DWORD, (const BYTE*)&v, sizeof(v)); };
    setStr(L"Port", cfg.port); setStr(L"UsbId", cfg.usbId); setStr(L"User", cfg.user); setStr(L"Domain", cfg.domain);
    setDw(L"FingerId", cfg.fingerId); setDw(L"Enabled", cfg.enabled ? 1 : 0); setDw(L"Debug", cfg.debug ? 1 : 0);
    RegSetValueExW(k, L"Blob", 0, REG_BINARY, cfg.blob.data(), (DWORD)cfg.blob.size());
    RegCloseKey(k);
    // Re-apply the DACL explicitly in case the key already existed with a permissive one.
    PSECURITY_DESCRIPTOR sd2 = nullptr;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:PAI(A;OICI;KA;;;SY)(A;OICI;KA;;;BA)", SDDL_REVISION_1, &sd2, nullptr)) {
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kRegPath, 0, WRITE_DAC | KEY_WOW64_64KEY, &k) == ERROR_SUCCESS) {
            RegSetKeySecurity(k, DACL_SECURITY_INFORMATION, sd2);
            RegCloseKey(k);
        }
        LocalFree(sd2);
    }
    return true;
}

bool DeleteConfig() {
    return RegDeleteKeyExW(HKEY_LOCAL_MACHINE, kRegPath, KEY_WOW64_64KEY, 0) == ERROR_SUCCESS;
}

// ---------- DPAPI ----------
bool ProtectSecrets(const Secrets& s, std::vector<uint8_t>& blob, std::wstring* err) {
    std::vector<uint8_t> raw;
    auto put = [&](const void* p, size_t n) { raw.insert(raw.end(), (const uint8_t*)p, (const uint8_t*)p + n); };
    uint32_t len = (uint32_t)s.ct.size();
    put(&kBlobMagic, 4); put(s.kpc, 32); put(s.kauth, 32); put(s.iv, 12); put(s.tag, 16); put(&len, 4); put(s.ct.data(), s.ct.size());
    DATA_BLOB in = { (DWORD)raw.size(), raw.data() }, out = {};
    BOOL ok = CryptProtectData(&in, L"ZwCredProv", nullptr, nullptr, nullptr, CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN, &out);
    SecureZeroMemory(raw.data(), raw.size());
    if (!ok) { if (err) *err = L"CryptProtectData failed"; return false; }
    blob.assign(out.pbData, out.pbData + out.cbData);
    SecureZeroMemory(out.pbData, out.cbData); LocalFree(out.pbData);
    return true;
}

bool UnprotectSecrets(const std::vector<uint8_t>& blob, Secrets& s, std::wstring* err) {
    DATA_BLOB in = { (DWORD)blob.size(), const_cast<BYTE*>(blob.data()) }, out = {};
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out)) {
        if (err) *err = L"CryptUnprotectData failed";
        return false;
    }
    bool ok = false;
    const uint8_t* p = out.pbData; DWORD n = out.cbData;
    if (n >= 4 + 32 + 32 + 12 + 16 + 4 && memcmp(p, &kBlobMagic, 4) == 0) {
        p += 4; memcpy(s.kpc, p, 32); p += 32; memcpy(s.kauth, p, 32); p += 32;
        memcpy(s.iv, p, 12); p += 12; memcpy(s.tag, p, 16); p += 16;
        uint32_t len; memcpy(&len, p, 4); p += 4;
        if (4 + 32 + 32 + 12 + 16 + 4 + len == n) { s.ct.assign(p, p + len); ok = true; }
    }
    SecureZeroMemory(out.pbData, out.cbData); LocalFree(out.pbData);
    if (!ok && err) *err = L"Blob повреждён";
    return ok;
}

// ---------- CNG ----------
bool RandomBytes(uint8_t* out, size_t n) {
    return NT_SUCCESS(BCryptGenRandom(nullptr, out, (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG));
}

static bool AesGcm(bool encrypt, const uint8_t key[32], const uint8_t iv[12], const std::vector<uint8_t>& in,
                   std::vector<uint8_t>& out, uint8_t tag[16]) {
    static const uint8_t aad[] = "zwcp-pw-v1";
    BCRYPT_ALG_HANDLE alg = nullptr; BCRYPT_KEY_HANDLE hk = nullptr; bool ok = false;
    std::vector<uint8_t> keyObj;
    do {
        if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0))) break;
        if (!NT_SUCCESS(BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0))) break;
        DWORD objLen = 0, cb = 0;
        if (!NT_SUCCESS(BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &cb, 0))) break;
        keyObj.resize(objLen);
        if (!NT_SUCCESS(BCryptGenerateSymmetricKey(alg, &hk, keyObj.data(), objLen, (PUCHAR)key, 32, 0))) break;
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info; BCRYPT_INIT_AUTH_MODE_INFO(info);
        uint8_t ivCopy[12]; memcpy(ivCopy, iv, 12);
        info.pbNonce = ivCopy; info.cbNonce = 12;
        info.pbAuthData = (PUCHAR)aad; info.cbAuthData = sizeof(aad) - 1;
        info.pbTag = tag; info.cbTag = 16;
        out.resize(in.size() + 16);
        ULONG res = 0; NTSTATUS st;
        if (encrypt) st = BCryptEncrypt(hk, (PUCHAR)in.data(), (ULONG)in.size(), &info, nullptr, 0, out.data(), (ULONG)out.size(), &res, 0);
        else         st = BCryptDecrypt(hk, (PUCHAR)in.data(), (ULONG)in.size(), &info, nullptr, 0, out.data(), (ULONG)out.size(), &res, 0);
        if (!NT_SUCCESS(st)) { out.clear(); break; }
        out.resize(res);
        ok = true;
    } while (false);
    if (hk) BCryptDestroyKey(hk);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    if (!keyObj.empty()) SecureZeroMemory(keyObj.data(), keyObj.size());
    return ok;
}

bool AesGcmEncrypt(const uint8_t key[32], const uint8_t iv[12], const std::vector<uint8_t>& plain, std::vector<uint8_t>& ct, uint8_t tag[16]) {
    return AesGcm(true, key, iv, plain, ct, tag);
}
bool AesGcmDecrypt(const uint8_t key[32], const uint8_t iv[12], const std::vector<uint8_t>& ct, const uint8_t tag[16], std::vector<uint8_t>& plain) {
    uint8_t t[16]; memcpy(t, tag, 16);
    return AesGcm(false, key, iv, ct, plain, t);
}

bool SealPassword(Secrets& s, const uint8_t kdev[32], const std::wstring& password) {
    uint8_t key[32];
    derive_password_key(kdev, s.kpc, key);
    if (!RandomBytes(s.iv, 12)) return false;
    std::vector<uint8_t> plain((const uint8_t*)password.data(), (const uint8_t*)password.data() + password.size() * 2);
    bool ok = AesGcmEncrypt(key, s.iv, plain, s.ct, s.tag);
    SecureZeroMemory(key, 32);
    if (!plain.empty()) SecureZeroMemory(plain.data(), plain.size());
    return ok;
}

bool OpenPassword(const Secrets& s, const uint8_t kdev[32], std::wstring& password) {
    uint8_t key[32];
    derive_password_key(kdev, s.kpc, key);
    std::vector<uint8_t> plain;
    bool ok = AesGcmDecrypt(key, s.iv, s.ct, s.tag, plain);
    SecureZeroMemory(key, 32);
    if (!ok) return false;
    password.assign((const wchar_t*)plain.data(), plain.size() / 2);
    if (!plain.empty()) SecureZeroMemory(plain.data(), plain.size());
    return true;
}

std::wstring EffectiveDomain(const Config& cfg) {
    if (!cfg.domain.empty() && cfg.domain != L".") return cfg.domain;
    wchar_t name[MAX_COMPUTERNAME_LENGTH + 1]; DWORD n = MAX_COMPUTERNAME_LENGTH + 1;
    if (GetComputerNameW(name, &n)) return name;
    return L".";
}

} // namespace zw
