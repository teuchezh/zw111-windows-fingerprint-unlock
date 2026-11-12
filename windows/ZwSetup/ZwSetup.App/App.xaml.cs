using System.Windows;
using Microsoft.Win32;
using Wpf.Ui.Appearance;
using ZwSetup.Core;

namespace ZwSetup.App;

public partial class App : Application
{
    public const string PrefsPath = @"Software\ZwCredProv";   // HKCU: per-user window preferences (theme)

    public static bool Smoke { get; private set; }
    static readonly object SmokeLock = new();
    public static void SmokeLog(string msg)
    {
        if (!Smoke) return;
        lock (SmokeLock) File.AppendAllText("smoke.log", DateTime.Now.ToString("HH:mm:ss.fff") + " " + msg + Environment.NewLine);
    }
    public static void SmokeExit(int code, string msg) { SmokeLog("exit " + code + ": " + msg); Environment.Exit(code); }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        Smoke = e.Args.Contains("--smoke");
        if (Smoke)
        {
            // CI self-test: any unhandled exception (XAML parse, binding, missing resource) fails the run.
            File.Delete("smoke.log");
            DispatcherUnhandledException += (_, ex) => SmokeExit(2, ex.Exception.ToString());
            AppDomain.CurrentDomain.UnhandledException += (_, ex) => SmokeExit(3, ex.ExceptionObject.ToString() ?? "");
            new Thread(() => { Thread.Sleep(45000); SmokeExit(4, "watchdog timeout"); }) { IsBackground = true }.Start();
            SmokeLog("startup");
        }
        var cfg = Config.Load(out _);
        L.Apply(cfg.Lang);
        ApplyTheme(LoadThemeSetting());
    }

    public static string LoadThemeSetting()
    {
        using var k = Registry.CurrentUser.OpenSubKey(PrefsPath, false);
        return k?.GetValue("Theme") as string ?? "auto";
    }

    public static void SaveThemeSetting(string s)
    {
        using var k = Registry.CurrentUser.CreateSubKey(PrefsPath);
        k?.SetValue("Theme", s);
    }

    public static void ApplyTheme(string setting)
    {
        switch (setting)
        {
            case "dark": ApplicationThemeManager.Apply(ApplicationTheme.Dark); break;
            case "light": ApplicationThemeManager.Apply(ApplicationTheme.Light); break;
            default: ApplicationThemeManager.ApplySystemTheme(); break;
        }
    }
}
