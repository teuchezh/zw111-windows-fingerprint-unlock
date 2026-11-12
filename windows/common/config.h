#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <stdint.h>

namespace zw {

// Registry: HKLM\SOFTWARE\ZwCredProv  (ACL: SYSTEM + Administrators only, set by zwsetup)
extern const wchar_t* const kRegPath;

struct Config {
    std::wstring port   = L"auto";                 // "auto" or "COM5"
    std::wstring usbId  = L"VID_2E8A";             // any Raspberry Pi vendor device; HELLO confirms it is ours
    std::wstring user;
    std::wstring domain;                           // "." = local machine
    DWORD fingerId = 0;                            // 0 = any enrolled finger
    bool enabled = true;
    bool debug = false;
    std::wstring lang = L"auto";                 // "auto" | "ru" | "en"
    std::vector<uint8_t> blob;                     // DPAPI-protected Secrets
};

struct Secrets {
    uint8_t kpc[32];
    uint8_t kauth[32];
    uint8_t iv[12];
    uint8_t tag[16];
    std::vector<uint8_t> ct;                       // AES-256-GCM(password as UTF-16LE, no terminator)
    ~Secrets();
};

bool LoadConfig(Config& cfg, std::wstring* err = nullptr);
bool SaveConfig(const Config& cfg, std::wstring* err = nullptr);   // creates key with restrictive ACL
bool DeleteConfig();

bool ProtectSecrets(const Secrets& s, std::vector<uint8_t>& blob, std::wstring* err = nullptr);
bool UnprotectSecrets(const std::vector<uint8_t>& blob, Secrets& s, std::wstring* err = nullptr);

bool RandomBytes(uint8_t* out, size_t n);
bool AesGcmEncrypt(const uint8_t key[32], const uint8_t iv[12], const std::vector<uint8_t>& plain,
                   std::vector<uint8_t>& ct, uint8_t tag[16]);
bool AesGcmDecrypt(const uint8_t key[32], const uint8_t iv[12], const std::vector<uint8_t>& ct,
                   const uint8_t tag[16], std::vector<uint8_t>& plain);

// Encrypt/decrypt the password with K_dev + K_pc.
bool SealPassword(Secrets& s, const uint8_t kdev[32], const std::wstring& password);
bool OpenPassword(const Secrets& s, const uint8_t kdev[32], std::wstring& password);

// If the local account `localUser` is linked to a Microsoft account, returns true and its e-mail.
bool LinkedMicrosoftAccount(const std::wstring& localUser, std::wstring& email);

// Resolve the effective logon domain ("." -> computer name).
std::wstring EffectiveDomain(const Config& cfg);

// Narrow (ASCII/UTF-8) -> wide, for printing protocol strings.
std::wstring A2W(const std::string& s);

// Debug log to %ProgramData%\ZwCredProv\zwcredprov.log (only if cfg.debug).
void LogEnable(bool on);
void Log(const wchar_t* fmt, ...);

} // namespace zw
