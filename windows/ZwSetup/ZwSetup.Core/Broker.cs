using System.Diagnostics;
using System.Security.Principal;

namespace ZwSetup.Core;

/// <summary>Installs and controls ZwCredSvc, the SYSTEM service behind fingerprint sign-in in Windows Security prompts.</summary>
public static class BrokerService
{
    public const string Name = "ZwCredSvc";
    public static string InstallDir => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "ZwCredProv");
    public static string InstalledExe => Path.Combine(InstallDir, "ZwCredSvc.exe");
    public static string LocalExe => Path.Combine(AppContext.BaseDirectory, "ZwCredSvc.exe");

    public enum State { NotInstalled, Stopped, Running, Other }

    static (int code, string output) Sc(string args)
    {
        var psi = new ProcessStartInfo("sc.exe", args) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
        using var p = Process.Start(psi)!;
        var o = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        p.WaitForExit(15000);
        return (p.ExitCode, o);
    }

    public static State Query()
    {
        var (code, o) = Sc("query " + Name);
        if (code == 1060) return State.NotInstalled;           // ERROR_SERVICE_DOES_NOT_EXIST
        if (o.Contains("RUNNING")) return State.Running;
        if (o.Contains("STOPPED")) return State.Stopped;
        return code == 0 ? State.Other : State.NotInstalled;
    }

    static void WaitFor(Func<State, bool> ok, int ms = 15000)
    {
        var sw = Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < ms && !ok(Query())) Thread.Sleep(300);
    }

    public static bool Install(out string err)
    {
        err = "";
        if (!File.Exists(LocalExe)) { err = L.F("Cu_NoExe", LocalExe); return false; }
        var st = Query();
        if (st == State.Running) { Sc("stop " + Name); WaitFor(s => s != State.Running); }
        try { Directory.CreateDirectory(InstallDir); File.Copy(LocalExe, InstalledExe, true); }
        catch (Exception e) { err = e.Message; return false; }
        if (st == State.NotInstalled)
        {
            var (c, o) = Sc($"create {Name} binPath= \"\\\"{InstalledExe}\\\"\" start= auto obj= LocalSystem DisplayName= \"ZwCredProv fingerprint broker\"");
            if (c != 0) { err = o.Trim(); return false; }
            Sc($"description {Name} \"Fingerprint sign-in in Windows Security prompts (ZW111 + RP2040)\"");
            Sc($"failure {Name} reset= 86400 actions= restart/5000");
        }
        else Sc($"config {Name} start= auto");
        var (sc2, so) = Sc("start " + Name);
        WaitFor(s => s == State.Running);
        if (Query() != State.Running) { err = so.Trim(); return false; }
        return true;
    }

    public static bool Uninstall(out string err)
    {
        err = "";
        if (Query() == State.NotInstalled) return true;
        Sc("stop " + Name);
        WaitFor(s => s != State.Running);
        var (c, o) = Sc("delete " + Name);
        if (c != 0 && c != 1072) { err = o.Trim(); return false; }   // 1072 = marked for deletion
        try { File.Delete(InstalledExe); } catch { }
        return true;
    }
}

public static class Identity
{
    /// <summary>SID of the account running this app (elevation keeps the same user), if it is the configured account.</summary>
    public static string? SidIfCurrentUser(Config cfg)
    {
        using var id = WindowsIdentity.GetCurrent();
        var me = Environment.UserName;
        bool local = (cfg.Domain is "." or "" || cfg.Domain.Equals(Environment.MachineName, StringComparison.OrdinalIgnoreCase))
                     && cfg.User.Equals(me, StringComparison.OrdinalIgnoreCase);
        bool msa = cfg.Domain.Equals("MicrosoftAccount", StringComparison.OrdinalIgnoreCase)
                   && Win.LinkedMicrosoftAccount(me, out var email) && email.Equals(cfg.User, StringComparison.OrdinalIgnoreCase);
        return local || msa ? id.User?.Value : null;
    }
}
