#pragma once
#include <windows.h>
#include <string>
#include <vector>

namespace zw {

// Minimal line-oriented serial port wrapper.
class SerialPort {
public:
    SerialPort() : _h(INVALID_HANDLE_VALUE) {}
    ~SerialPort() { Close(); }
    bool Open(const std::wstring& portName);     // "COM5"
    void Close();
    bool IsOpen() const { return _h != INVALID_HANDLE_VALUE; }
    bool WriteLine(const std::string& line);     // appends "\n"
    // Reads one line (without CR/LF). Returns false on timeout or error; *err set on error.
    bool ReadLine(std::string& line, DWORD timeoutMs, bool* err = nullptr);
    void Purge();
private:
    HANDLE _h;
    std::string _rx;
};

// Returns COM port names (e.g. "COM5") whose hardware ID contains usbId (e.g. "VID_2E8A&PID_000A").
std::vector<std::wstring> FindComPortsByUsbId(const std::wstring& usbId);

// All present COM ports: (port name, first hardware ID), e.g. ("COM12", "USB\\VID_2E8A&PID_000A&REV_0100&MI_00").
std::vector<std::pair<std::wstring, std::wstring>> ListComPorts();

} // namespace zw
