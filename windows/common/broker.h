// Broker protocol between ZwCredSvc (SYSTEM service) and the credential provider running inside
// Windows Security prompts (CredUI), where the provider cannot read the protected configuration.
//
// Transport: message-less byte pipe \\.\pipe\ZwCredProv, UTF-8 lines terminated by '\n'.
//   client: INFO
//   server: INFO <enabled 0|1> <debug 0|1> <lang>      then three lines: <user> <domain> <sid>
//   client: AUTH
//   server: zero or more  EV WAIT | EV NOMATCH | EV READY | EV LOCKED <sec>
//           then exactly one of
//             PW <hex of UTF-16LE password>              (finger matched)
//             ERR <code> [text]                          (DISABLED, CLIENT, USER, NODEVICE, NOTPROVISIONED,
//                                                         AUTHFAILED, TIMEOUT, CANCELLED, KEY, CONFIG, BUSY)
//   client may send CANCEL at any time while waiting, or simply close the pipe.
// The server only answers AUTH for a client whose process image is %SystemRoot%\System32\CredentialUIBroker.exe
// and whose token user is the configured account.
#pragma once
#include <windows.h>
#include <string>
#include <functional>
#include <atomic>

namespace zw {

static const wchar_t* const kBrokerPipe = L"\\\\.\\pipe\\ZwCredProv";
static const wchar_t* const kServiceName = L"ZwCredSvc";

struct BrokerInfo {
    bool enabled = false, debug = false;
    std::wstring lang = L"auto", user, domain, sid;
};

// Client side (used by the provider in the CredUI scenario).
bool BrokerQueryInfo(BrokerInfo& info, std::string* err = nullptr);

enum class BrokerResult { Password, Disabled, Refused, NoDevice, Timeout, Cancelled, Error };

// Blocks until a finger matched (password filled), an error, or *cancel. onEvent gets WAIT/NOMATCH/READY/"LOCKED n".
BrokerResult BrokerAuthenticate(std::atomic<bool>& cancel, std::wstring& password, std::string& err,
                                const std::function<void(const std::string&)>& onEvent);

} // namespace zw
