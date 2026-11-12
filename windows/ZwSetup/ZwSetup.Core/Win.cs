using System.Runtime.InteropServices;
using System.Security.Principal;

namespace ZwSetup.Core;

/// <summary>Thin P/Invoke layer: Microsoft-account detection, LogonUser, COM self-registration, delayed file replace.</summary>
public static class Win
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct USER_INFO_24
    {
        public bool usri24_internet_identity;
        public uint usri24_flags;
        public string usri24_internet_provider_name;
        public string usri24_internet_principal_name;
        public IntPtr usri24_user_sid;
    }
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)] static extern int NetUserGetInfo(string? server, string user, int level, out IntPtr buf);
    [DllImport("netapi32.dll")] static extern int NetApiBufferFree(IntPtr buf);

    /// <summary>True if the local account is linked to a Microsoft account; returns its e-mail.</summary>
    public static bool LinkedMicrosoftAccount(string localUser, out string email)
    {
        email = "";
        if (!OperatingSystem.IsWindows()) return false;
        if (NetUserGetInfo(null, localUser, 24, out var buf) != 0 || buf == IntPtr.Zero) return false;
        try
        {
            var ui = Marshal.PtrToStructure<USER_INFO_24>(buf);
            if (ui.usri24_internet_identity && !string.IsNullOrEmpty(ui.usri24_internet_principal_name)) { email = ui.usri24_internet_principal_name; return true; }
            return false;
        }
        finally { NetApiBufferFree(buf); }
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool LogonUserW(string user, string domain, string password, int type, int provider, out IntPtr token);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);

    /// <summary>Interactive logon check; returns 0 on success or the Win32 error (1326 = bad credentials).</summary>
    public static int TryLogon(string user, string domain, string password)
    {
        if (!LogonUserW(user, domain, password, 2 /*INTERACTIVE*/, 0, out var tok)) return Marshal.GetLastWin32Error();
        CloseHandle(tok);
        return 0;
    }

    public static bool AccountExists(string qualifiedName)
    {
        try { new NTAccount(qualifiedName).Translate(typeof(SecurityIdentifier)); return true; }
        catch { return false; }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr LoadLibraryW(string path);
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)] static extern IntPtr GetProcAddress(IntPtr h, string name);
    [DllImport("kernel32.dll")] static extern bool FreeLibrary(IntPtr h);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool MoveFileExW(string src, string? dst, int flags);
    const int MOVEFILE_REPLACE_EXISTING = 1, MOVEFILE_DELAY_UNTIL_REBOOT = 4;
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int RegFn();

    public static string System32Dll => Path.Combine(Environment.SystemDirectory, "ZwCredProv.dll");
    public static string LocalDll => Path.Combine(AppContext.BaseDirectory, "ZwCredProv.dll");

    /// <summary>Calls DllRegisterServer / DllUnregisterServer of the DLL at <paramref name="path"/>. Returns HRESULT.</summary>
    public static int RegisterDll(string path, bool register)
    {
        var h = LoadLibraryW(path);
        if (h == IntPtr.Zero) return Marshal.GetHRForLastWin32Error();
        try
        {
            var p = GetProcAddress(h, register ? "DllRegisterServer" : "DllUnregisterServer");
            if (p == IntPtr.Zero) return unchecked((int)0x80004005);
            return Marshal.GetDelegateForFunctionPointer<RegFn>(p)();
        }
        finally { FreeLibrary(h); }
    }

    /// <summary>Copies the DLL into System32; if the old copy is locked (LogonUI), schedules the replacement for the next reboot.</summary>
    public static CopyResult CopyDllToSystem32(out string error)
    {
        error = "";
        try { File.Copy(LocalDll, System32Dll, true); return CopyResult.Copied; }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        var tmp = System32Dll + ".new";
        try
        {
            File.Copy(LocalDll, tmp, true);
            if (MoveFileExW(tmp, System32Dll, MOVEFILE_REPLACE_EXISTING | MOVEFILE_DELAY_UNTIL_REBOOT)) return CopyResult.DelayedUntilReboot;
            error = Marshal.GetLastWin32Error().ToString();
        }
        catch (Exception e) { error = e.Message; }
        return CopyResult.Failed;
    }

    public static void DeleteDllFromSystem32()
    {
        try { File.Delete(System32Dll); } catch { MoveFileExW(System32Dll, null, MOVEFILE_DELAY_UNTIL_REBOOT); }
    }

    public enum CopyResult { Copied, DelayedUntilReboot, Failed }

    public static bool IsAdministrator()
    {
        if (!OperatingSystem.IsWindows()) return false;
        using var id = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
    }
}
