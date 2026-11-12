using System.Windows;
using Microsoft.Win32;
using Wpf.Ui.Appearance;
using ZwSetup.Core;

namespace ZwSetup.App;

public partial class App : Application
{
    public const string PrefsPath = @"Software\ZwCredProv";   // HKCU: per-user window preferences (theme)

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
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
