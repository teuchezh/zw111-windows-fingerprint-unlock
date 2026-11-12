using System.Windows;
using System.Windows.Controls;
using ZwSetup.Core;

namespace ZwSetup.App.Pages;

public partial class StatusPage : Page
{
    public StatusPage()
    {
        InitializeComponent();
        Loaded += (_, _) => { Shell.I.StatusChanged += Render; Render(); };
        Unloaded += (_, _) => Shell.I.StatusChanged -= Render;
    }

    void Render()
    {
        var st = Shell.I.LastStatus;
        if (st == null) return;
        CfgText.Text = st.CfgExists && st.Cfg.IsComplete ? L.F("Status_ConfiguredFor", st.Cfg.QualifiedUser()) : L.S("Status_NotConfigured");
        DllText.Text = L.S(st.DllRegistered ? "Status_DllRegistered" : "Status_DllNotRegistered");
        TileSwitch.IsChecked = st.CfgExists && st.Cfg.Enabled;
        TileSwitch.IsEnabled = st.CfgExists && st.Cfg.IsComplete;
        DeviceText.Text = st.Device != null
            ? L.F("Status_DeviceOn", st.DevicePort, L.S(st.Device.Provisioned ? "Status_KeysYes" : "Status_KeysNo"), st.Device.Templates)
            : L.S("Status_DeviceOff") + (st.Diag.Length > 0 ? "\n" + st.Diag : "");
        PortsList.ItemsSource = st.Ports;
        NoPortsText.Visibility = st.Ports.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    void Refresh_Click(object sender, RoutedEventArgs e) => Shell.I.RefreshStatus();
    void Register_Click(object sender, RoutedEventArgs e) => Shell.I.Run(() => Shell.I.Ops.RegisterDll(true));
    void Unregister_Click(object sender, RoutedEventArgs e) => Shell.I.Run(() => Shell.I.Ops.RegisterDll(false));
    void Tile_Click(object sender, RoutedEventArgs e)
    {
        bool on = TileSwitch.IsChecked == true;
        Shell.I.Run(() => Shell.I.Ops.SetEnabled(on));
    }
}
