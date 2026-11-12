using System.Windows;
using System.Windows.Controls;
using Wpf.Ui.Controls;
using ZwSetup.Core;

namespace ZwSetup.App.Pages;

public partial class LedPage : Page
{
    sealed class Row
    {
        public required string Event;
        public required System.Windows.Controls.ComboBox Mode, Color;
        public required Wpf.Ui.Controls.TextBox Speed, Count;
        public LedFx Read() => new(Mode.SelectedIndex + 1, Color.SelectedIndex + 1,
                                   int.TryParse(Speed.Text, out var s) ? Math.Clamp(s, 0, 255) : 0,
                                   int.TryParse(Count.Text, out var c) ? Math.Clamp(c, 0, 255) : 0);
        public void Write(LedFx f)
        {
            Mode.SelectedIndex = Math.Clamp(f.Mode, 1, 6) - 1;
            Color.SelectedIndex = Math.Clamp(f.Color == 0 ? 1 : f.Color, 1, 7) - 1;
            Speed.Text = f.Speed.ToString(); Count.Text = f.Count.ToString();
        }
    }

    readonly List<Row> _rows = new();
    string? _proto;

    public LedPage()
    {
        InitializeComponent();
        BuildRows();
        Loaded += (_, _) => Reload();
    }

    static readonly Dictionary<string, SymbolRegular> Icons = new()
    {
        ["WAIT"] = SymbolRegular.Fingerprint24, ["MATCH"] = SymbolRegular.CheckmarkCircle24, ["FAIL"] = SymbolRegular.ErrorCircle24,
        ["ENROLL"] = SymbolRegular.Add24, ["IDLE"] = SymbolRegular.WeatherMoon24,
    };

    void BuildRows()
    {
        foreach (var ev in Device.LedEvents)
        {
            var mode = new System.Windows.Controls.ComboBox { Width = 160, Margin = new Thickness(0, 0, 8, 0) };
            for (int i = 1; i <= 6; i++) mode.Items.Add(L.S("Led_Mode" + i));
            var color = new System.Windows.Controls.ComboBox { Width = 140, Margin = new Thickness(0, 0, 8, 0) };
            for (int i = 1; i <= 7; i++) color.Items.Add(L.S("Led_Color" + i));
            var speed = new Wpf.Ui.Controls.TextBox { Width = 64, Margin = new Thickness(0, 0, 8, 0), ToolTip = L.S("Led_Speed"), PlaceholderText = L.S("Led_Speed") };
            var count = new Wpf.Ui.Controls.TextBox { Width = 64, Margin = new Thickness(0, 0, 8, 0), ToolTip = L.S("Led_CountTip"), PlaceholderText = L.S("Led_Count") };
            var row = new Row { Event = ev, Mode = mode, Color = color, Speed = speed, Count = count };
            var preview = new Wpf.Ui.Controls.Button { Content = L.S("Led_Preview"), MinWidth = 96 };
            preview.Click += (_, _) => { var fx = row.Read(); Shell.I.Run(() => Shell.I.Ops.LedPreview(fx), refreshStatus: false); };

            var right = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            right.Children.Add(mode); right.Children.Add(color); right.Children.Add(speed); right.Children.Add(count); right.Children.Add(preview);

            var header = new StackPanel();
            header.Children.Add(new System.Windows.Controls.TextBlock { Text = L.S("Led_Ev_" + ev), Style = (Style)FindResource("CardTitle") });
            header.Children.Add(new System.Windows.Controls.TextBlock { Text = L.S("Led_Ev_" + ev + "_Desc"), Style = (Style)FindResource("CardDesc") });

            var card = new CardControl { Style = (Style)FindResource("Card"), Header = header, Content = right, Icon = new SymbolIcon { Symbol = Icons[ev] } };
            EffectCards.Children.Add(card);
            row.Write(new LedFx(4, 1, 0, 0));
            _rows.Add(row);
        }
    }

    void ApplyProto(string? proto)
    {
        _proto = proto;
        ProtoText.Text = proto switch { "3C" => L.S("Led_Proto3C"), "35" => L.S("Led_Proto35"), _ => L.S("Led_ProtoNone") };
        // Only the 0x35 command has a speed parameter.
        foreach (var r in _rows) r.Speed.Visibility = proto == "35" ? Visibility.Visible : Visibility.Collapsed;
    }

    void Reload()
    {
        Editor.IsEnabled = false;
        ProtoText.Text = L.S("Led_Reading");
        Task.Run(() =>
        {
            var st = Shell.I.Ops.LedRead(out var reason);
            Dispatcher.Invoke(() =>
            {
                if (st == null)
                {
                    ProtoText.Text = reason.StartsWith(L.S("Led_OldFirmware")) ? reason : L.S("Led_NoDevice") + reason;
                    return;
                }
                ApplyProto(st.Proto);
                foreach (var r in _rows) if (st.Config.Fx.TryGetValue(r.Event, out var f)) r.Write(f);
                WaitLightBox.Text = st.Config.WaitLightSec.ToString();
                Editor.IsEnabled = st.Proto != "NONE";
            });
        });
    }

    LedConfig Collect() => new(_rows.ToDictionary(r => r.Event, r => r.Read()),
                               int.TryParse(WaitLightBox.Text, out var w) ? Math.Clamp(w, 0, 3600) : 0);

    void Reload_Click(object sender, RoutedEventArgs e) => Reload();
    void Save_Click(object sender, RoutedEventArgs e) { var c = Collect(); Shell.I.Run(() => Shell.I.Ops.LedWrite(c), refreshStatus: false); }
    void Reset_Click(object sender, RoutedEventArgs e)
    {
        Shell.I.Run(() => Shell.I.Ops.LedFactoryReset(), refreshStatus: false);
        // re-read once the device has applied the defaults
        Task.Run(async () => { while (Shell.I.Busy) await Task.Delay(200); Dispatcher.Invoke(Reload); });
    }
}
