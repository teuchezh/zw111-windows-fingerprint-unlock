using System.Security.Cryptography;
using System.Text;

namespace ZwSetup.Core;

/// <summary>UI-independent operations. The host supplies logging and confirmation callbacks.</summary>
public sealed class Ops
{
    public Action<string> Log = _ => { };
    /// <summary>Modal yes/no question; must block the calling (worker) thread until answered.</summary>
    public Func<string, bool> Ask = _ => true;
    public Action<string> Error = _ => { };

    public record SetupInput(string User, string Domain, string Password, string Password2, string Port, string UsbId, int FingerId, bool Debug);

    Device? OpenDev(string port, string usbId, out DeviceInfo info)
    {
        var diag = new StringBuilder();
        var dev = Device.Open(port, usbId, out info, diag);
        if (dev == null) { Error(L.F("DeviceNotFound", port, usbId, diag.ToString().TrimEnd())); return null; }
        Log(L.F("DeviceFoundOn", dev.PortName));
        return dev;
    }

    bool AuthGetKdev(Device dev, Secrets s, out byte[] kdev)
    {
        var r = dev.RunAuth(s.Kauth, CancellationToken.None, out kdev, out var id, out var err, ev =>
        {
            if (ev == "WAIT") Log(L.S("PlaceFinger")); else if (ev == "NOMATCH") Log(L.S("NoMatchRetry"));
        });
        switch (r)
        {
            case AuthResult.Match: Log(L.F("MatchId", id)); return true;
            case AuthResult.NoDevice: Error(L.F("ErrComm", err)); break;
            case AuthResult.NotProvisioned: Error(L.S("ErrNotProvisioned")); break;
            case AuthResult.AuthFailed: Error(L.S("ErrAuthFailed")); break;
            case AuthResult.Timeout: Error(L.S("ErrTimeout")); break;
            case AuthResult.Error: Error(L.F("ErrProtocol", err)); break;
        }
        return false;
    }

    public record StatusInfo(Config Cfg, bool CfgExists, bool DllRegistered, List<ComPortInfo> Ports, string? DevicePort, DeviceInfo? Device, string Diag);

    public StatusInfo Status(string? portOverride = null, string? usbOverride = null)
    {
        var cfg = Config.Load(out bool exists);
        var ports = Device.ListPorts();
        var diag = new StringBuilder();
        using var dev = Device.Open(portOverride ?? cfg.Port, usbOverride ?? cfg.UsbId, out var info, diag);
        return new StatusInfo(cfg, exists, Config.DllRegistered(), ports, dev?.PortName, dev != null ? info : null, diag.ToString().TrimEnd());
    }

    /// <summary>Step 1. Returns the effective (possibly MSA-corrected) user/domain on success.</summary>
    public bool Provision(SetupInput inp)
    {
        if (string.IsNullOrWhiteSpace(inp.User)) { Error(L.S("ErrUserEmpty")); return false; }
        if (inp.Password != inp.Password2) { Error(L.S("ErrPwMismatch")); return false; }
        if (inp.Password.Length == 0 && !Ask(L.S("PwEmptyQ"))) return false;
        var cfg = Config.Load(out _);
        cfg.User = inp.User.Trim(); cfg.Domain = string.IsNullOrWhiteSpace(inp.Domain) ? "." : inp.Domain.Trim();
        cfg.Port = string.IsNullOrWhiteSpace(inp.Port) ? "auto" : inp.Port.Trim(); cfg.UsbId = inp.UsbId.Trim();
        cfg.FingerId = inp.FingerId; cfg.Debug = inp.Debug; cfg.Enabled = true; cfg.Lang = L.Setting;

        if (cfg.Domain == "." && Win.LinkedMicrosoftAccount(cfg.User, out var email) && Ask(L.F("MsaOffer", cfg.User, email)))
        {
            cfg.Domain = "MicrosoftAccount"; cfg.User = email;
            Log("MicrosoftAccount\\" + email);
        }
        if (cfg.Domain.Equals("MicrosoftAccount", StringComparison.OrdinalIgnoreCase) && !cfg.User.Contains('@') && !Ask(L.S("MsaNeedsEmail"))) return false;
        if (!Win.AccountExists(cfg.QualifiedUser()) && !cfg.Domain.Equals("MicrosoftAccount", StringComparison.OrdinalIgnoreCase))
        {
            if (!Ask(L.F("AccountNotFound", cfg.QualifiedUser()))) return false;
        }

        using var dev = OpenDev(cfg.Port, cfg.UsbId, out _);
        if (dev == null) return false;
        using var s = new Secrets { Kpc = Crypto.Random(32), Kauth = Crypto.Random(32) };
        var kdev = Crypto.Random(32);
        try
        {
            if (!Ask(L.S("HoldButton"))) return false;
            if (!dev.Provision(kdev, s.Kauth, out var err)) { Error(L.F("DeviceRefused", err)); return false; }
            Log(L.S("KeysWritten"));
            Crypto.SealPassword(s, kdev, inp.Password);
        }
        finally { CryptographicOperations.ZeroMemory(kdev); }
        try { cfg.StoreSecrets(s); cfg.Save(); }
        catch (Exception e) { Error(L.F("ErrSave", e.Message)); return false; }
        Log(L.S("CfgSaved"));
        if (dev.Hello(out var info, out _))
            Log(info.Templates == 0 ? L.S("NoTemplates") : L.F("TemplatesN", info.Templates));
        if (!Config.DllRegistered()) Log(L.S("DllNotRegHint"));
        return true;
    }

    public bool Enroll(int slot, bool delete, string? port = null, string? usbId = null)
    {
        if (slot < 1 || slot > 199) { Error(L.S("ErrSlot")); return false; }
        var cfg = Config.Load(out _);
        using var dev = OpenDev(port ?? cfg.Port, usbId ?? cfg.UsbId, out _);
        if (dev == null) return false;
        if (!Ask(L.S("HoldButton"))) return false;
        if (delete)
        {
            if (!dev.DeleteFinger(slot, out var derr)) { Error(L.F("DeleteErr", derr)); return false; }
            Log(L.F("SlotDeleted", slot)); return true;
        }
        bool ok = dev.Enroll(slot, ev =>
        {
            if (ev == "PLACE") Log(L.S("EnrollPlace")); else if (ev == "REMOVE") Log(L.S("EnrollRemove")); else if (ev == "AGAIN") Log(L.S("EnrollAgain"));
        }, out var err);
        if (!ok) { Error(L.F("EnrollErr", err)); return false; }
        Log(L.F("Enrolled", slot));
        return true;
    }

    public bool Test(string? port = null, string? usbId = null)
    {
        var cfg = Config.Load(out bool exists);
        if (!exists || !cfg.IsComplete) { Error(L.S("Settings_NeedConfig")); return false; }
        using var s = cfg.OpenSecrets();
        if (s == null) { Error(L.S("ErrUnprotect")); return false; }
        using var dev = OpenDev(port ?? cfg.Port, usbId ?? cfg.UsbId, out _);
        if (dev == null) return false;
        if (!AuthGetKdev(dev, s, out var kdev)) return false;
        string? pw;
        try { pw = Crypto.OpenPassword(s, kdev); } finally { CryptographicOperations.ZeroMemory(kdev); }
        if (pw == null) { Error(L.S("PwNotDecrypted")); return false; }
        Log(L.S("PwDecrypted"));
        int e = Win.TryLogon(cfg.User, cfg.EffectiveDomain(), pw);
        pw = null;
        if (e == 0)
        {
            Log(L.S("LogonOk"));
            if (!Config.DllRegistered()) Log(L.S("DllNotRegHint"));
            return true;
        }
        Log(L.F("LogonFail", e));
        if (cfg.Domain == "." && Win.LinkedMicrosoftAccount(cfg.User, out var email)) Log(L.F("MsaLinkedFix", cfg.User, email));
        else Log(L.S("PwHint"));
        return false;
    }

    public bool SetPassword(string pw, string pw2, string? port = null, string? usbId = null)
    {
        if (pw != pw2) { Error(L.S("ErrPwMismatch")); return false; }
        var cfg = Config.Load(out bool exists);
        if (!exists || !cfg.IsComplete) { Error(L.S("Settings_NeedConfig")); return false; }
        using var s = cfg.OpenSecrets();
        if (s == null) { Error(L.S("ErrUnprotect")); return false; }
        using var dev = OpenDev(port ?? cfg.Port, usbId ?? cfg.UsbId, out _);
        if (dev == null) return false;
        if (!AuthGetKdev(dev, s, out var kdev)) return false;
        try { Crypto.SealPassword(s, kdev, pw); } finally { CryptographicOperations.ZeroMemory(kdev); }
        try { cfg.StoreSecrets(s); cfg.Save(); } catch (Exception e) { Error(L.F("ErrSave", e.Message)); return false; }
        Log(L.S("PwUpdated"));
        return true;
    }

    public bool SetEnabled(bool on)
    {
        var cfg = Config.Load(out bool exists);
        if (!exists) { Error(L.S("Settings_NeedConfig")); return false; }
        cfg.Enabled = on;
        try { cfg.Save(); } catch (Exception e) { Error(L.F("ErrSave", e.Message)); return false; }
        Log(L.S(on ? "TileOn" : "TileOff"));
        return true;
    }

    public bool SetDebug(bool on)
    {
        var cfg = Config.Load(out bool exists);
        if (!exists) { Error(L.S("Settings_NeedConfig")); return false; }
        cfg.Debug = on;
        try { cfg.Save(); } catch (Exception e) { Error(L.F("ErrSave", e.Message)); return false; }
        return true;
    }

    public bool SetLang(string setting)
    {
        L.Apply(setting);
        var cfg = Config.Load(out bool exists);
        if (!exists) return true;
        cfg.Lang = setting;
        try { cfg.Save(); } catch (Exception e) { Error(L.F("ErrSave", e.Message)); return false; }
        Log(L.S("LangSaved"));
        return true;
    }

    public bool Wipe(string? port = null, string? usbId = null)
    {
        var cfg = Config.Load(out _);
        using var dev = OpenDev(port ?? cfg.Port, usbId ?? cfg.UsbId, out _);
        if (dev == null) return false;
        if (!Ask(L.S("WipeConfirm"))) return false;
        if (!dev.Wipe(out var err)) { Error(L.F("ErrProtocol", err)); return false; }
        Log(L.S("Wiped"));
        return true;
    }

    public bool RemoveConfig()
    {
        if (!Ask(L.S("RemoveConfirm"))) return false;
        Log(L.S(Config.Delete() ? "CfgDeleted" : "NothingToDelete"));
        return true;
    }

    public bool RegisterDll(bool register)
    {
        if (register)
        {
            if (!File.Exists(Win.LocalDll)) { Error(L.F("DllMissing", Win.LocalDll)); return false; }
            switch (Win.CopyDllToSystem32(out var cerr))
            {
                case Win.CopyResult.Copied: Log(L.F("DllCopied", Win.System32Dll)); break;
                case Win.CopyResult.DelayedUntilReboot: Log(L.S("DllBusyReboot")); break;
                default: Error(L.F("DllCopyFail", cerr)); return false;
            }
        }
        int hr = Win.RegisterDll(Win.System32Dll, register);
        if (hr < 0) { Error(L.F("DllRegHr", hr)); return false; }
        if (register) Log(L.S("DllRegistered"));
        else { Log(L.S("DllUnregistered")); Win.DeleteDllFromSystem32(); }
        return true;
    }
}
