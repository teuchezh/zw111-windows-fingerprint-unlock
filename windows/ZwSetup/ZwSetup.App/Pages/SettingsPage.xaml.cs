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
            ReadFirmware();
            Shell.I.DeviceChanged += ReadFirmware;
        };
        Unloaded += (_, _) => Shell.I.DeviceChanged -= ReadFirmware;
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

    // ---------- firmware ----------
    Ops.FwState? _fw;

    void ReadFirmware()
    {
        FwText.Text = L.S("Fw_Reading");
        FwUpdateBtn.IsEnabled = false;
        var asm = typeof(SettingsPage).Assembly;
        Task.Run(() =>
        {
            var st = Shell.I.Ops.FirmwareRead(asm, out var reason);
            Dispatcher.Invoke(() =>
            {
                _fw = st;
                var bundled = Firmware.BundledVersion(asm) ?? L.S("Fw_None");
                if (st == null) { FwText.Text = L.S("Led_NoDevice") + reason; return; }
                FwText.Text = L.F("Fw_Info", st.Device?.Version ?? L.S("Fw_Old"), st.Board, bundled);
                FwUpdateBtn.IsEnabled = Firmware.Bundled(st.Board, asm) != null;
            });
        });
    }

    void FwUpdate_Click(object sender, RoutedEventArgs e)
    {
        var img = _fw == null ? null : Firmware.Bundled(_fw.Board, typeof(SettingsPage).Assembly);
        if (img == null) { _ = Dialogs.ShowAsync(L.S("Dlg_Attention"), L.S("Fw_NoBundled"), L.S("Dlg_Ok"), null); return; }
        Shell.I.Run(() => Shell.I.Ops.UpdateFirmware(img));
        Task.Run(async () => { await Task.Delay(300); while (Shell.I.Busy) await Task.Delay(300); Dispatcher.Invoke(ReadFirmware); });
    }

    void FwFile_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog { Filter = "UF2 (*.uf2)|*.uf2", Title = L.S("Fw_FromFile") };
        if (dlg.ShowDialog() != true) return;
        var img = System.IO.File.ReadAllBytes(dlg.FileName);
        Shell.I.Run(() => Shell.I.Ops.UpdateFirmware(img));
        Task.Run(async () => { await Task.Delay(300); while (Shell.I.Busy) await Task.Delay(300); Dispatcher.Invoke(ReadFirmware); });
    }
}
