using System.Diagnostics;
using System.IO.Ports;
using System.Management;
using System.Security.Cryptography;
using System.Text;

namespace ZwSetup.Core;

public enum AuthResult { Match, NoDevice, NotProvisioned, AuthFailed, Timeout, Cancelled, Error }

public record DeviceInfo(bool Provisioned, int Templates);
public record ComPortInfo(string Port, string HardwareId, string Name);

/// <summary>Text protocol over USB CDC, see firmware/src/main.cpp.</summary>
public sealed class Device : IDisposable
{
    readonly SerialPort _port;
    public string PortName => _port.PortName;

    Device(SerialPort p) { _port = p; }

    public void Dispose() { try { if (_port.IsOpen) { _port.WriteLine("CANCEL"); _port.Close(); } } catch { } _port.Dispose(); }

    // ---------- discovery ----------
    public static List<ComPortInfo> ListPorts()
    {
        var result = new List<ComPortInfo>();
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT Name, PNPDeviceID, HardwareID FROM Win32_PnPEntity WHERE ClassGuid = '{4d36e978-e325-11ce-bfc1-08002be10318}'");
            foreach (ManagementObject o in searcher.Get())
            {
                var name = o["Name"] as string ?? "";
                var m = System.Text.RegularExpressions.Regex.Match(name, @"\((COM\d+)\)");
                if (!m.Success) continue;
                string hwid = (o["HardwareID"] as string[])?.FirstOrDefault() ?? o["PNPDeviceID"] as string ?? "";
                result.Add(new ComPortInfo(m.Groups[1].Value, hwid, name));
            }
        }
        catch (Exception)
        {
            foreach (var p in SerialPort.GetPortNames()) result.Add(new ComPortInfo(p, "", p));
        }
        return result.OrderBy(p => p.Port.Length).ThenBy(p => p.Port).ToList();
    }

    public static List<string> FindPortsByUsbId(string usbId) =>
        ListPorts().Where(p => p.HardwareId.Contains(usbId, StringComparison.OrdinalIgnoreCase)).Select(p => p.Port).ToList();

    /// <summary>Opens the configured port ("auto" = search by USB id) and verifies HELLO. diag collects reasons for rejected ports.</summary>
    public static Device? Open(string portSetting, string usbId, out DeviceInfo info, StringBuilder? diag = null)
    {
        info = new DeviceInfo(false, 0);
        var candidates = portSetting.Equals("auto", StringComparison.OrdinalIgnoreCase) ? FindPortsByUsbId(usbId) : new List<string> { portSetting };
        if (candidates.Count == 0) diag?.Append(L.S("NoPortsWithId")).Append(usbId).Append('\n');
        foreach (var c in candidates)
        {
            SerialPort sp;
            try
            {
                sp = new SerialPort(c, 115200, Parity.None, 8, StopBits.One) { DtrEnable = true, RtsEnable = true, NewLine = "\n", ReadTimeout = 250, WriteTimeout = 1000, Encoding = Encoding.ASCII };
                sp.Open();
            }
            catch (UnauthorizedAccessException) { diag?.Append(c).Append(L.S("PortBusy")).Append('\n'); continue; }
            catch (Exception e) { diag?.Append(c).Append(L.S("PortOpenFailed")).Append(e.Message).Append('\n'); continue; }
            var dev = new Device(sp);
            string last = "";
            for (int attempt = 0; attempt < 3; attempt++)
            {
                if (dev.Hello(out info, out last)) return dev;
                Thread.Sleep(400);
            }
            diag?.Append(c).Append(L.S("PortNoHello")).Append(last).Append(L.S("PortNoHello2")).Append('\n');
            dev.Dispose();
        }
        return null;
    }

    // ---------- protocol ----------
    void Purge() { try { _port.DiscardInBuffer(); _port.DiscardOutBuffer(); } catch { } }
    void Send(string line) => _port.Write(line + "\n");

    /// <summary>Reads one non-empty line or returns null on timeout.</summary>
    string? ReadLine(int timeoutMs)
    {
        var sw = Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < timeoutMs)
        {
            try
            {
                var l = _port.ReadLine().TrimEnd('\r', ' ');
                if (l.Length > 0) return l;
            }
            catch (TimeoutException) { }
        }
        return null;
    }

    string? Expect(string prefix, int timeoutMs, out string err)
    {
        err = "";
        var sw = Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < timeoutMs)
        {
            var l = ReadLine((int)Math.Max(1, timeoutMs - sw.ElapsedMilliseconds));
            if (l == null) break;
            if (l.StartsWith(prefix, StringComparison.Ordinal)) return l;
            if (l.StartsWith("ERR ", StringComparison.Ordinal)) { err = l; return null; }
            err = "last line: " + l;
        }
        if (err.Length == 0) err = "timeout waiting for " + prefix;
        return null;
    }

    public bool Hello(out DeviceInfo info, out string err)
    {
        info = new DeviceInfo(false, 0);
        Purge(); Send("HELLO");
        var l = Expect("OK ZWCP ", 1500, out err);
        if (l == null) return false;
        var parts = l.Substring(8).Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 3 || parts[0] != "1") return false;
        info = new DeviceInfo(parts[1] != "0", int.TryParse(parts[2], out var t) ? t : 0);
        return true;
    }

    public int TemplateCount() { Purge(); Send("COUNT"); var l = Expect("COUNT ", 2000, out _); return l != null && int.TryParse(l.Substring(6), out var n) ? n : -1; }

    /// <summary>NONCE → AUTH → wait for MATCH. onEvent gets "WAIT" / "NOMATCH".</summary>
    public AuthResult RunAuth(byte[] kauth, CancellationToken cancel, out byte[] kdev, out int fingerId, out string err, Action<string>? onEvent = null)
    {
        kdev = new byte[32]; fingerId = 0; err = "";
        Purge(); Send("NONCE");
        var l = Expect("NONCE ", 2000, out err);
        if (l == null) return AuthResult.NoDevice;
        var nonce = Crypto.UnHex(l.Substring(6).Trim(), 16);
        if (nonce == null) { err = "bad nonce"; return AuthResult.Error; }
        Send("AUTH " + Crypto.Hex(Crypto.HostProof(kauth, nonce)));
        var sw = Stopwatch.StartNew();
        for (;;)
        {
            l = ReadLine(12000);
            if (l == null) { err = "no AUTH reply"; return AuthResult.NoDevice; }
            if (l == "OK WAIT") break;
            if (l == "ERR AUTH") return AuthResult.AuthFailed;
            if (l == "ERR NOTPROVISIONED") return AuthResult.NotProvisioned;
            if (l.StartsWith("ERR ")) { err = l; return AuthResult.Error; }
            if (sw.ElapsedMilliseconds > 12000) { err = "no AUTH reply"; return AuthResult.NoDevice; }
        }
        onEvent?.Invoke("WAIT");
        for (;;)
        {
            if (cancel.IsCancellationRequested) { Send("CANCEL"); return AuthResult.Cancelled; }
            try { l = _port.ReadLine().TrimEnd('\r', ' '); }
            catch (TimeoutException) { continue; }
            catch (Exception e) { err = e.Message; return AuthResult.NoDevice; }
            if (l.Length == 0) continue;
            if (l.StartsWith("MATCH "))
            {
                var p = l.Substring(6).Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (p.Length < 3) { err = "bad MATCH"; return AuthResult.Error; }
                var wrapped = Crypto.UnHex(p[2], 32);
                if (wrapped == null) { err = "bad MATCH"; return AuthResult.Error; }
                var mask = Crypto.WrapMask(kauth, nonce);
                for (int i = 0; i < 32; i++) kdev[i] = (byte)(wrapped[i] ^ mask[i]);
                CryptographicOperations.ZeroMemory(wrapped); CryptographicOperations.ZeroMemory(mask);
                int.TryParse(p[0], out fingerId);
                return AuthResult.Match;
            }
            if (l == "NOMATCH") { onEvent?.Invoke("NOMATCH"); continue; }
            if (l == "TIMEOUT") return AuthResult.Timeout;
            if (l.StartsWith("ERR ")) { err = l; return AuthResult.Error; }
        }
    }

    public bool Provision(byte[] kdev, byte[] kauth, out string err)
    {
        Purge(); Send("PROVISION " + Crypto.Hex(kdev) + " " + Crypto.Hex(kauth));
        return Expect("OK PROVISIONED", 5000, out err) != null;
    }

    public bool Wipe(out string err) { Purge(); Send("WIPE"); return Expect("OK WIPED", 10000, out err) != null; }

    public bool DeleteFinger(int id, out string err) { Purge(); Send("DELETE " + id); return Expect("OK", 5000, out err) != null; }

    /// <summary>onEvent gets "PLACE" / "REMOVE" / "AGAIN".</summary>
    public bool Enroll(int id, Action<string> onEvent, out string err)
    {
        err = "";
        Purge(); Send("ENROLL " + id);
        var sw = Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < 120000)
        {
            var l = ReadLine(1000);
            if (l == null) continue;
            if (l.StartsWith("ENROLL ")) { onEvent(l.Substring(7)); continue; }
            if (l.StartsWith("OK ENROLL ")) return true;
            if (l.StartsWith("ERR ")) { err = l; return false; }
        }
        err = "timeout";
        return false;
    }
}
