using System.Windows;
using Microsoft.Win32;
using Wpf.Ui.Appearance;
using ZwSetup.Core;

namespace ZwSetup.App;

public partial class App : Application
{
    public const string PrefsPath = @"Software\ZwCredProv";   // HKCU: per-user window preferences (theme)

    public static bool Smoke { get; private set; }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        Smoke = e.Args.Contains("--smoke");
        if (Smoke)
        {
            // CI self-test: any unhandled exception (XAML parse, binding, missing resource) fails the run.
            DispatcherUnhandledException += (_, ex) => { Console.Error.WriteLine(ex.Exception); Environment.Exit(2); };
            AppDomain.CurrentDomain.UnhandledException += (_, ex) => { Console.Error.WriteLine(ex.ExceptionObject); Environment.Exit(3); };
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
