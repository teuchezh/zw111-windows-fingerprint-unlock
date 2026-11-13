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
            if (ev == "WAIT" || ev == "READY") Log(L.S("PlaceFinger"));
            else if (ev == "NOMATCH") Log(L.S("NoMatchRetry"));
            else if (ev.StartsWith("LOCKED ")) Log(L.F("Locked", ev.Substring(7)));
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
        cfg.UserSid = Identity.SidIfCurrentUser(cfg) ?? "";
        try { cfg.StoreSecrets(s); cfg.Save(); }
        catch (Exception e) { Error(L.F("ErrSave", e.Message)); return false; }
        Log(L.S("CfgSaved"));
        LogonFailure.Clear();
        if (dev.Hello(out var info, out _))
            Log(info.Templates == 0 ? L.S("NoTemplates") : L.F("TemplatesN", info.Templates));
        if (!Config.DllRegistered()) Log(L.S("DllNotRegHint"));
        return true;
    }

    // ---------- fingerprint slots ----------
    public record SlotInfo(int Slot, string Name);
    public record SlotState(List<SlotInfo> Slots, int Capacity);

    /// <summary>Silent read for page loading.</summary>
    public SlotState? SlotsRead(out string reason)
    {
        reason = "";
        var cfg = Config.Load(out _);
        var diag = new StringBuilder();
        using var dev = Device.Open(cfg.Port, cfg.UsbId, out _, diag);
        if (dev == null) { reason = diag.ToString().Trim(); return null; }
        var ids = dev.Slots(out var cap);
        if (ids == null) { reason = L.S("Fingers_OldFirmware"); return null; }
        var names = FingerNames.Load();
        return new SlotState(ids.Select(i => new SlotInfo(i, names.TryGetValue(i, out var n) ? n : "")).ToList(), cap);
    }

    /// <summary>Enrolls into the lowest free slot (1..capacity-1) and stores the name.</summary>
    public bool EnrollNew(string name)
    {
        var cfg = Config.Load(out _);
        int slot;
        using (var dev = OpenDev(cfg.Port, cfg.UsbId, out _))
        {
            if (dev == null) return false;
            var ids = dev.Slots(out var cap);
            if (ids == null) { Error(L.S("Fingers_OldFirmware")); return false; }
            slot = Enumerable.Range(1, Math.Max(1, cap - 1)).FirstOrDefault(i => !ids.Contains(i));
            if (slot == 0) { Error(L.S("Fingers_Full")); return false; }
        }
        if (!Enroll(slot, false)) return false;
        FingerNames.Set(slot, string.IsNullOrWhiteSpace(name) ? L.F("Fingers_DefaultName", slot) : name);
        return true;
    }

    public bool DeleteSlot(int slot)
    {
        if (!Enroll(slot, true)) return false;
        FingerNames.Set(slot, null);
        return true;
    }

    // ---------- firmware update ----------
    public record FwState(FirmwareVersion? Device, string Board, string? Bundled, string HardwareId);

    public FwState? FirmwareRead(System.Reflection.Assembly app, out string reason)
    {
        reason = "";
        var cfg = Config.Load(out _);
        var diag = new StringBuilder();
        using var dev = Device.Open(cfg.Port, cfg.UsbId, out _, diag);
        if (dev == null) { reason = diag.ToString().Trim(); return null; }
        var hw = Device.ListPorts().FirstOrDefault(p => p.Port == dev.PortName)?.HardwareId ?? "";
        var v = dev.Version();
        var board = v != null && v.Board.Length > 0 ? v.Board : Firmware.GuessBoard(hw);
        return new FwState(v, board, Firmware.BundledVersion(app), hw);
    }

    /// <summary>Reboots the board into the UF2 bootloader (button held), copies the image, waits for the board to come back.</summary>
    public bool UpdateFirmware(byte[] image)
    {
        if (!Firmware.IsRp2040Uf2(image, out var why)) { Error(L.F("Fw_BadImage", why)); return false; }
        var cfg = Config.Load(out _);
        var diag = new StringBuilder();
        var dev = Device.Open(cfg.Port, cfg.UsbId, out _, diag);
        if (dev != null)
        {
            using (dev)
            {
                if (dev.Version() == null)
                {
                    // Firmware older than 1.1 has no BOOTLOADER command: the user enters the bootloader by hand.
                    if (!Ask(L.S("Fw_ManualBoot"))) return false;
                }
                else
                {
                    if (!Ask(L.S("HoldButton"))) return false;
                    if (!dev.Bootloader(out var err)) { Error(L.F("DeviceRefused", err)); return false; }
                }
            }
        }
        else if (!Ask(L.S("Fw_ManualBoot"))) return false;

        Log(L.S("Fw_WaitDrive"));
        var root = Firmware.WaitForBootDrive(TimeSpan.FromSeconds(60));
        if (root == null) { Error(L.S("Fw_NoDrive")); return false; }
        Log(L.F("Fw_Copying", root));
        if (!Firmware.CopyToBootDrive(root, image, out var cerr)) { Error(L.F("Fw_CopyFail", cerr)); return false; }

        Log(L.S("Fw_WaitBoard"));
        var until = DateTime.UtcNow.AddSeconds(30);
        while (DateTime.UtcNow < until)
        {
            Thread.Sleep(1000);
            using var back = Device.Open(cfg.Port, cfg.UsbId, out _);
            if (back == null) continue;
            var v = back.Version();
            Log(L.F("Fw_Done", v?.Version ?? "?", back.PortName));
            return true;
        }
        Error(L.S("Fw_NoBoard"));
        return false;
    }

    // ---------- ring LED ----------
    public record LedState(string? Proto, LedConfig Config, string Port);

    /// <summary>Silent read for page loading: returns null and a reason instead of showing an error dialog.</summary>
    public LedState? LedRead(out string reason)
    {
        reason = "";
        var cfg = Config.Load(out _);
        var diag = new StringBuilder();
        using var dev = Device.Open(cfg.Port, cfg.UsbId, out _, diag);
        if (dev == null) { reason = diag.ToString().Trim(); return null; }
        var proto = dev.LedInfo();
        var led = dev.LedGet();
        if (proto == null || led == null) { reason = L.S("Led_OldFirmware"); return null; }
        return new LedState(proto, led, dev.PortName);
    }

    public bool LedWrite(LedConfig led)
    {
        var cfg = Config.Load(out _);
        using var dev = OpenDev(cfg.Port, cfg.UsbId, out _);
        if (dev == null) return false;
        foreach (var (ev, fx) in led.Fx)
            if (!dev.LedSet(ev, fx, out var err)) { Error(L.F("ErrProtocol", err)); return false; }
        if (!dev.LedWaitLight(led.WaitLightSec, out var werr)) { Error(L.F("ErrProtocol", werr)); return false; }
        Log(L.S("Led_Saved"));
        return true;
    }

    public bool LedPreview(LedFx fx)
    {
        var cfg = Config.Load(out _);
        using var dev = OpenDev(cfg.Port, cfg.UsbId, out _);
        if (dev == null) return false;
        if (!dev.LedPlay(fx, out var err)) { Error(L.F("ErrProtocol", err)); return false; }
        return true;
    }

    public bool LedFactoryReset()
    {
        var cfg = Config.Load(out _);
        using var dev = OpenDev(cfg.Port, cfg.UsbId, out _);
        if (dev == null) return false;
        if (!dev.LedReset(out var err)) { Error(L.F("ErrProtocol", err)); return false; }
        Log(L.S("Led_ResetDone"));
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
        LogonFailure.Clear();
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

    /// <summary>Fills in UserSid for configurations made before it existed, when this app runs as that user.</summary>
    public void EnsureUserSid()
    {
        try
        {
            var cfg = Config.Load(out bool exists);
            if (!exists || cfg.UserSid.Length > 0 || !cfg.IsComplete) return;
            var sid = Identity.SidIfCurrentUser(cfg);
            if (sid == null) return;
            cfg.UserSid = sid; cfg.Save();
        }
        catch { }
    }

    public bool SetCredUi(bool on)
    {
        var cfg = Config.Load(out bool exists);
        if (!exists || !cfg.IsComplete) { Error(L.S("Settings_NeedConfig")); return false; }
        if (on)
        {
            if (cfg.UserSid.Length == 0) cfg.UserSid = Identity.SidIfCurrentUser(cfg) ?? "";
            if (cfg.UserSid.Length == 0) { Error(L.S("Cu_NoSid")); return false; }
            if (!Ask(L.S("Cu_Confirm"))) return false;
            if (!BrokerService.Install(out var err)) { Error(L.F("Cu_InstallFail", err)); return false; }
            cfg.CredUiEnabled = true;
            try { cfg.Save(); } catch (Exception e) { Error(L.F("ErrSave", e.Message)); return false; }
            Log(L.S("Cu_On"));
        }
        else
        {
            cfg.CredUiEnabled = false;
            try { cfg.Save(); } catch (Exception e) { Error(L.F("ErrSave", e.Message)); return false; }
            if (!BrokerService.Uninstall(out var err)) { Error(L.F("Cu_RemoveFail", err)); return false; }
            Log(L.S("Cu_Off"));
        }
        return true;
    }

    public bool RemoveConfig()
    {
        if (!Ask(L.S("RemoveConfirm"))) return false;
        BrokerService.Uninstall(out _);
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
