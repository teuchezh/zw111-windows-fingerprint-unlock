#include "serial.h"
#include <setupapi.h>
#include <initguid.h>
#include <devguid.h>
#include <winioctl.h>
#include <algorithm>
#include <cwctype>

namespace zw {

bool SerialPort::Open(const std::wstring& portName) {
    Close();
    std::wstring path = L"\\\\.\\" + portName;
    _h = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (_h == INVALID_HANDLE_VALUE) return false;
    DCB dcb = {}; dcb.DCBlength = sizeof(dcb);
    GetCommState(_h, &dcb);
    dcb.BaudRate = CBR_115200; dcb.ByteSize = 8; dcb.Parity = NOPARITY; dcb.StopBits = ONESTOPBIT;
    dcb.fBinary = TRUE; dcb.fDtrControl = DTR_CONTROL_ENABLE; dcb.fRtsControl = RTS_CONTROL_ENABLE;
    dcb.fOutxCtsFlow = FALSE; dcb.fOutxDsrFlow = FALSE; dcb.fDsrSensitivity = FALSE;
    dcb.fOutX = FALSE; dcb.fInX = FALSE;
    SetCommState(_h, &dcb);  // may fail on some virtual ports; harmless for USB CDC
    COMMTIMEOUTS to = {};
    to.ReadIntervalTimeout = MAXDWORD; to.ReadTotalTimeoutMultiplier = MAXDWORD; to.ReadTotalTimeoutConstant = 100;
    to.WriteTotalTimeoutConstant = 1000;
    SetCommTimeouts(_h, &to);
    Purge();
    _rx.clear();
    return true;
}

void SerialPort::Close() {
    if (_h != INVALID_HANDLE_VALUE) { CloseHandle(_h); _h = INVALID_HANDLE_VALUE; }
    _rx.clear();
}

void SerialPort::Purge() {
    if (IsOpen()) PurgeComm(_h, PURGE_RXCLEAR | PURGE_TXCLEAR);
    _rx.clear();
}

bool SerialPort::WriteLine(const std::string& line) {
    if (!IsOpen()) return false;
    std::string s = line + "\n";
    DWORD written = 0;
    if (!WriteFile(_h, s.data(), (DWORD)s.size(), &written, nullptr)) return false;
    return written == s.size();
}

bool SerialPort::ReadLine(std::string& line, DWORD timeoutMs, bool* err) {
    if (err) *err = false;
    if (!IsOpen()) { if (err) *err = true; return false; }
    ULONGLONG deadline = GetTickCount64() + timeoutMs;
    for (;;) {
        size_t nl = _rx.find('\n');
        if (nl != std::string::npos) {
            line = _rx.substr(0, nl);
            _rx.erase(0, nl + 1);
            while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
            if (line.empty()) continue;
            return true;
        }
        if (GetTickCount64() >= deadline) return false;
        char buf[256]; DWORD got = 0;
        if (!ReadFile(_h, buf, sizeof(buf), &got, nullptr)) { if (err) *err = true; return false; }
        if (got) {
            _rx.append(buf, got);
            if (_rx.size() > 4096) _rx.erase(0, _rx.size() - 4096);
        }
    }
}

static std::wstring Upper(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c) { return (wchar_t)towupper(c); });
    return s;
}

std::vector<std::pair<std::wstring, std::wstring>> ListComPorts() {
    std::vector<std::pair<std::wstring, std::wstring>> result;
    HDEVINFO h = SetupDiGetClassDevsW(&GUID_DEVINTERFACE_COMPORT, nullptr, nullptr, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (h == INVALID_HANDLE_VALUE) return result;
    SP_DEVINFO_DATA di = {}; di.cbSize = sizeof(di);
    for (DWORD i = 0; SetupDiEnumDeviceInfo(h, i, &di); i++) {
        wchar_t hwid[1024] = {0}; DWORD type = 0, size = 0;
        SetupDiGetDeviceRegistryPropertyW(h, &di, SPDRP_HARDWAREID, &type, (PBYTE)hwid, sizeof(hwid) - 2, &size);
        HKEY key = SetupDiOpenDevRegKey(h, &di, DICS_FLAG_GLOBAL, 0, DIREG_DEV, KEY_READ);
        if (key == INVALID_HANDLE_VALUE) continue;
        wchar_t port[64] = {0}; DWORD cb = sizeof(port) - 2; DWORD t = 0;
        if (RegQueryValueExW(key, L"PortName", nullptr, &t, (LPBYTE)port, &cb) == ERROR_SUCCESS && t == REG_SZ && port[0])
            result.push_back({ port, hwid });
        RegCloseKey(key);
    }
    SetupDiDestroyDeviceInfoList(h);
    return result;
}

std::vector<std::wstring> FindComPortsByUsbId(const std::wstring& usbId) {
    std::vector<std::wstring> result;
    std::wstring want = Upper(usbId);
    HDEVINFO h = SetupDiGetClassDevsW(&GUID_DEVINTERFACE_COMPORT, nullptr, nullptr, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (h == INVALID_HANDLE_VALUE) return result;
    SP_DEVINFO_DATA di = {}; di.cbSize = sizeof(di);
    for (DWORD i = 0; SetupDiEnumDeviceInfo(h, i, &di); i++) {
        wchar_t hwid[1024] = {0}; DWORD type = 0, size = 0;
        if (!SetupDiGetDeviceRegistryPropertyW(h, &di, SPDRP_HARDWAREID, &type, (PBYTE)hwid, sizeof(hwid) - 2, &size)) continue;
        // REG_MULTI_SZ: check every string
        bool match = false;
        for (wchar_t* p = hwid; *p; p += wcslen(p) + 1) if (Upper(p).find(want) != std::wstring::npos) { match = true; break; }
        if (!match) continue;
        HKEY key = SetupDiOpenDevRegKey(h, &di, DICS_FLAG_GLOBAL, 0, DIREG_DEV, KEY_READ);
        if (key == INVALID_HANDLE_VALUE) continue;
        wchar_t port[64] = {0}; DWORD cb = sizeof(port) - 2; DWORD t = 0;
        if (RegQueryValueExW(key, L"PortName", nullptr, &t, (LPBYTE)port, &cb) == ERROR_SUCCESS && t == REG_SZ && port[0])
            result.push_back(port);
        RegCloseKey(key);
    }
    SetupDiDestroyDeviceInfoList(h);
    return result;
}

} // namespace zw
