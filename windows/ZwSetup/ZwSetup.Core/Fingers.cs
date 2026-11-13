using Microsoft.Win32;

namespace ZwSetup.Core;

/// <summary>Human-readable finger names, stored on the PC next to the configuration (the sensor only knows slot numbers).</summary>
public static class FingerNames
{
    const string Path = Config.RegPath + @"\Fingers";

    public static Dictionary<int, string> Load()
    {
        var r = new Dictionary<int, string>();
        using var k = Registry.LocalMachine.OpenSubKey(Path, false);
        if (k == null) return r;
        foreach (var n in k.GetValueNames())
            if (int.TryParse(n, out var id) && k.GetValue(n) is string s && s.Length > 0) r[id] = s;
        return r;
    }

    public static void Set(int slot, string? name)
    {
        using var k = Registry.LocalMachine.CreateSubKey(Path);
        if (k == null) return;
        if (string.IsNullOrWhiteSpace(name)) k.DeleteValue(slot.ToString(), false);
        else k.SetValue(slot.ToString(), name.Trim());
    }

    public static void Clear()
    {
        try { Registry.LocalMachine.DeleteSubKeyTree(Path, false); } catch { }
    }
}

/// <summary>The credential provider records a rejected fingerprint logon here so the app can suggest a password update.</summary>
public static class LogonFailure
{
    public static (int status, DateTime when)? Read()
    {
        using var k = Registry.LocalMachine.OpenSubKey(Config.RegPath, false);
        if (k?.GetValue("LastLogonError") is not int st || st == 0) return null;
        var when = k.GetValue("LastLogonErrorTime") is long ft ? DateTime.FromFileTime(ft) : DateTime.MinValue;
        return (st, when);
    }

    public static void Clear()
    {
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(Config.RegPath, true);
            k?.DeleteValue("LastLogonError", false);
            k?.DeleteValue("LastLogonErrorTime", false);
        }
        catch { }
    }
}
