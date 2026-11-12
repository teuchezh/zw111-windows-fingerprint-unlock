using System.Security.AccessControl;
using System.Security.Cryptography;
using Microsoft.Win32;

namespace ZwSetup.Core;

/// <summary>HKLM\SOFTWARE\ZwCredProv, shared with the C++ credential provider.</summary>
public sealed class Config
{
    public const string RegPath = @"SOFTWARE\ZwCredProv";
    public const string CpRegPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{7B2F3C1E-9A4D-4E6B-8C21-5D0E9F3A6B47}";
    const string Sddl = "D:PAI(A;OICI;KA;;;SY)(A;OICI;KA;;;BA)";

    public string Port = "auto";
    public string UsbId = "VID_2E8A";
    public string User = "";
    public string Domain = ".";
    public int FingerId;
    public bool Enabled = true;
    public bool Debug;
    public string Lang = "auto";
    public byte[] Blob = Array.Empty<byte>();

    public bool IsComplete => User.Length > 0 && Blob.Length > 0;

    /// <summary>Returns a Config even when the key is missing (defaults); <paramref name="exists"/> tells whether it was there.</summary>
    public static Config Load(out bool exists)
    {
        var c = new Config();
        using var k = Registry.LocalMachine.OpenSubKey(RegPath, false);
        exists = k != null;
        if (k == null) return c;
        c.Port = k.GetValue("Port") as string ?? c.Port;
        c.UsbId = k.GetValue("UsbId") as string ?? c.UsbId;
        c.User = k.GetValue("User") as string ?? "";
        c.Domain = k.GetValue("Domain") as string ?? ".";
        c.FingerId = k.GetValue("FingerId") is int f ? f : 0;
        c.Enabled = (k.GetValue("Enabled") is int e ? e : 1) != 0;
        c.Debug = (k.GetValue("Debug") is int d ? d : 0) != 0;
        c.Lang = k.GetValue("Lang") as string ?? "auto";
        c.Blob = k.GetValue("Blob") as byte[] ?? Array.Empty<byte>();
        return c;
    }

    public void Save()
    {
        var sec = new RegistrySecurity();
        sec.SetSecurityDescriptorSddlForm(Sddl);
        using var k = Registry.LocalMachine.CreateSubKey(RegPath, RegistryKeyPermissionCheck.ReadWriteSubTree, sec)
                      ?? throw new InvalidOperationException("RegCreateKeyEx failed");
        k.SetValue("Port", Port); k.SetValue("UsbId", UsbId); k.SetValue("User", User); k.SetValue("Domain", Domain);
        k.SetValue("FingerId", FingerId, RegistryValueKind.DWord);
        k.SetValue("Enabled", Enabled ? 1 : 0, RegistryValueKind.DWord);
        k.SetValue("Debug", Debug ? 1 : 0, RegistryValueKind.DWord);
        k.SetValue("Lang", Lang);
        k.SetValue("Blob", Blob, RegistryValueKind.Binary);
        k.SetAccessControl(sec);   // re-apply in case the key existed with a permissive DACL
    }

    public static bool Delete()
    {
        try { Registry.LocalMachine.DeleteSubKeyTree(RegPath, false); return true; } catch { return false; }
    }

    public static bool DllRegistered()
    {
        using var k = Registry.LocalMachine.OpenSubKey(CpRegPath, false);
        return k != null;
    }

    public string EffectiveDomain() => string.IsNullOrEmpty(Domain) || Domain == "." ? Environment.MachineName : Domain;
    public string QualifiedUser() => EffectiveDomain() + "\\" + User;

    public Secrets? OpenSecrets()
    {
        if (Blob.Length == 0) return null;
        byte[] raw;
        try { raw = ProtectedData.Unprotect(Blob, null, DataProtectionScope.LocalMachine); }
        catch (CryptographicException) { return null; }
        var s = Secrets.Unpack(raw);
        CryptographicOperations.ZeroMemory(raw);
        return s;
    }

    public void StoreSecrets(Secrets s)
    {
        var raw = s.Pack();
        Blob = ProtectedData.Protect(raw, null, DataProtectionScope.LocalMachine);
        CryptographicOperations.ZeroMemory(raw);
    }
}
