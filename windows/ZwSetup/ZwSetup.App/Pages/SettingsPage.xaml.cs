using System.Windows;
using System.Windows.Controls;
using Wpf.Ui.Appearance;
using ZwSetup.Core;

namespace ZwSetup.App.Pages;

public partial class SettingsPage : Page
{
    bool _loading = true;

    public SettingsPage()
    {
        InitializeComponent();
        Loaded += (_, _) =>
        {
            _loading = true;
            LangCombo.SelectedIndex = L.Setting.Equals("ru", StringComparison.OrdinalIgnoreCase) ? 1 : L.Setting.Equals("en", StringComparison.OrdinalIgnoreCase) ? 2 : 0;
            ThemeCombo.SelectedIndex = App.LoadThemeSetting() switch { "dark" => 1, "light" => 2, _ => 0 };
            var cfg = Config.Load(out bool exists);
            DebugSwitch.IsChecked = exists && cfg.Debug;
            DebugSwitch.IsEnabled = exists;
            VersionText.Text = "v" + (typeof(SettingsPage).Assembly.GetName().Version?.ToString(3) ?? "");
            _loading = false;
        };
    }

    void Lang_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (_loading) return;
        var setting = LangCombo.SelectedIndex switch { 1 => "ru", 2 => "en", _ => "auto" };
        Shell.I.Ops.SetLang(setting);
    }

    void Theme_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (_loading) return;
        var setting = ThemeCombo.SelectedIndex switch { 1 => "dark", 2 => "light", _ => "auto" };
        App.SaveThemeSetting(setting);
        var main = Application.Current.MainWindow;
        if (main != null) { if (setting == "auto") SystemThemeWatcher.Watch(main); else SystemThemeWatcher.UnWatch(main); }
        App.ApplyTheme(setting);
    }

    void Debug_Click(object sender, RoutedEventArgs e)
    {
        bool on = DebugSwitch.IsChecked == true;
        Shell.I.Run(() => Shell.I.Ops.SetDebug(on), refreshStatus: false);
    }

    void Remove_Click(object sender, RoutedEventArgs e) => Shell.I.Run(() => Shell.I.Ops.RemoveConfig());
}
