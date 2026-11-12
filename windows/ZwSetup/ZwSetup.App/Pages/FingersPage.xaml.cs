using System.Windows;
using System.Windows.Controls;
using ZwSetup.Core;

namespace ZwSetup.App.Pages;

public partial class FingersPage : Page
{
    public FingersPage()
    {
        InitializeComponent();
        Loaded += (_, _) => { Shell.I.StatusChanged += Render; Render(); };
        Unloaded += (_, _) => Shell.I.StatusChanged -= Render;
    }

    void Render()
    {
        var st = Shell.I.LastStatus;
        CountText.Text = st?.Device != null ? st.Device.Templates.ToString() : L.S("Status_DeviceOff");
    }

    int Slot() => int.TryParse(SlotBox.Text, out var s) ? s : 0;
    void Enroll_Click(object sender, RoutedEventArgs e) { int s = Slot(); Shell.I.Run(() => Shell.I.Ops.Enroll(s, false)); }
    void Delete_Click(object sender, RoutedEventArgs e) { int s = Slot(); Shell.I.Run(() => Shell.I.Ops.Enroll(s, true)); }
    void Wipe_Click(object sender, RoutedEventArgs e) => Shell.I.Run(() => Shell.I.Ops.Wipe());
}
