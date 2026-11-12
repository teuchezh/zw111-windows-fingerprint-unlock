#pragma once
#include "serial.h"
#include <atomic>
#include <functional>
#include <string>
#include <stdint.h>

namespace zw {

enum class AuthResult { Match, NoDevice, NotProvisioned, AuthFailed, Timeout, Cancelled, Error };

struct DeviceInfo { bool provisioned = false; int templates = 0; };

// HELLO handshake. Returns false if the port does not talk our protocol.
bool Hello(SerialPort& port, DeviceInfo& info, std::string* err = nullptr);

// Opens the device named by cfg port setting ("auto" => search by USB id).
// diag (optional) receives a human-readable reason for every candidate port that was rejected.
bool OpenDevice(SerialPort& port, const std::wstring& portSetting, const std::wstring& usbId, std::wstring* chosen = nullptr, std::wstring* diag = nullptr);

// Full handshake: NONCE -> AUTH -> wait MATCH. Blocks until a match, a timeout, an error or *cancel.
// On Match: kdevOut (unwrapped K_dev) and fingerId are set.
// waitMs: how long to wait for a finger after OK WAIT (0 = until cancel). The firmware itself no longer
// times out, so interactive tools pass a limit and the credential provider passes 0.
AuthResult RunAuth(SerialPort& port, const uint8_t kauth[32], std::atomic<bool>& cancel,
                   uint8_t kdevOut[32], int& fingerId, std::string* err = nullptr,
                   const std::function<void(const std::string&)>& onEvent = nullptr, DWORD waitMs = 0);

bool Provision(SerialPort& port, const uint8_t kdev[32], const uint8_t kauth[32], std::string* err = nullptr);
bool Wipe(SerialPort& port, std::string* err = nullptr);
bool Enroll(SerialPort& port, int id, const std::function<void(const std::string&)>& onEvent, std::string* err = nullptr);
bool DeleteFinger(SerialPort& port, int id, std::string* err = nullptr);

} // namespace zw
