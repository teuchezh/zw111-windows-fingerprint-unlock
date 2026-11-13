using System.Windows;
using System.Windows.Controls;
using Wpf.Ui.Controls;
using ZwSetup.Core;

namespace ZwSetup.App.Pages;

public partial class FingersPage : Page
{
    bool _loading;

    public FingersPage()
    {
        InitializeComponent();
        Loaded += (_, _) => { Shell.I.DeviceChanged += Reload; Reload(); };
        Unloaded += (_, _) => Shell.I.DeviceChanged -= Reload;
    }

    void Reload()
    {
        if (_loading || Shell.I.Busy) return;
        _loading = true;
        ListStatus.Text = L.S("Fingers_Reading");
        Task.Run(() =>
        {
            var st = Shell.I.Ops.SlotsRead(out var reason);
            Dispatcher.Invoke(() => { Render(st, reason); _loading = false; });
        });
    }

    void Render(Ops.SlotState? st, string reason)
    {
        SlotList.Children.Clear();
        if (st == null)
        {
            ListStatus.Text = reason.StartsWith(L.S("Fingers_OldFirmware")) ? reason : L.S("Led_NoDevice") + reason;
            return;
        }
        var allowed = Config.Load(out _).FingerId;
        ListStatus.Text = st.Slots.Count == 0 ? L.S("Fingers_Empty") : L.S("Fingers_Count") + ": " + st.Slots.Count;
        foreach (var s in st.Slots)
        {
            int slot = s.Slot;
            var name = new Wpf.Ui.Controls.TextBox { Width = 200, Margin = new Thickness(0, 0, 8, 0), Text = s.Name, PlaceholderText = L.F("Fingers_DefaultName", slot) };
            var save = new Wpf.Ui.Controls.Button { Content = L.S("Fingers_Rename"), Margin = new Thickness(0, 0, 8, 0) };
            save.Click += (_, _) => { FingerNames.Set(slot, name.Text); Shell.I.Log(L.S("Fingers_NameSaved")); Reload(); };
            var del = new Wpf.Ui.Controls.Button { Content = L.S("Fingers_DeleteBtn"), Appearance = ControlAppearance.Danger };
            del.Click += (_, _) => Shell.I.Run(() => { var ok = Shell.I.Ops.DeleteSlot(slot); Dispatcher.Invoke(Reload); return ok; });

            var right = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            right.Children.Add(name); right.Children.Add(save); right.Children.Add(del);

            var header = new StackPanel();
            header.Children.Add(new System.Windows.Controls.TextBlock { Text = s.Name.Length > 0 ? s.Name : L.F("Fingers_DefaultName", slot), Style = (Style)FindResource("CardTitle") });
            var sub = allowed == 0 || allowed == slot ? L.F("Fingers_SlotAllowed", slot) : L.F("Fingers_SlotNotAllowed", slot);
            header.Children.Add(new System.Windows.Controls.TextBlock { Text = sub, Style = (Style)FindResource("CardDesc") });

            SlotList.Children.Add(new CardControl { Style = (Style)FindResource("Card"), Header = header, Content = right, Icon = new SymbolIcon { Symbol = SymbolRegular.Fingerprint24 } });
        }
    }

    void Reload_Click(object sender, RoutedEventArgs e) => Reload();

    void Add_Click(object sender, RoutedEventArgs e)
    {
        var name = NewNameBox.Text;
        Shell.I.Run(() =>
        {
            var ok = Shell.I.Ops.EnrollNew(name);
            Dispatcher.Invoke(() => { if (ok) NewNameBox.Text = ""; });
            return ok;
        });
        Task.Run(async () => { await Task.Delay(300); while (Shell.I.Busy) await Task.Delay(300); Dispatcher.Invoke(Reload); });
    }

    void Wipe_Click(object sender, RoutedEventArgs e)
    {
        Shell.I.Run(() => { var ok = Shell.I.Ops.Wipe(); if (ok) FingerNames.Clear(); return ok; });
        Task.Run(async () => { await Task.Delay(300); while (Shell.I.Busy) await Task.Delay(300); Dispatcher.Invoke(Reload); });
    }
}
