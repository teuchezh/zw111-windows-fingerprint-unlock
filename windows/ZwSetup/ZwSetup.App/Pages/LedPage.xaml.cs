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

    // Each effect row is a Card with a 3-column grid: icon | title+description | controls.
    // When the page is narrow the controls move to a second line under the title (see Relayout).
    readonly List<(Grid grid, FrameworkElement controls, FrameworkElement header, Card card)> _layout = new();
    const double MinTitleWidth = 180;   // the title column must keep at least this much in the one-line layout
    const double IconAndPadding = 40 + 32;
    bool _wide;

    void BuildRows()
    {
        foreach (var ev in Device.LedEvents)
        {
            var mode = new System.Windows.Controls.ComboBox { Width = 150, Margin = new Thickness(0, 0, 8, 0) };
            for (int i = 1; i <= 6; i++) mode.Items.Add(L.S("Led_Mode" + i));
            var color = new System.Windows.Controls.ComboBox { Width = 130, Margin = new Thickness(0, 0, 8, 0) };
            for (int i = 1; i <= 7; i++) color.Items.Add(L.S("Led_Color" + i));
            var speed = new Wpf.Ui.Controls.TextBox { Width = 64, Margin = new Thickness(0, 0, 8, 0), ToolTip = L.S("Led_Speed"), PlaceholderText = L.S("Led_Speed") };
            var count = new Wpf.Ui.Controls.TextBox { Width = 64, Margin = new Thickness(0, 0, 8, 0), ToolTip = L.S("Led_CountTip"), PlaceholderText = L.S("Led_Count") };
            var row = new Row { Event = ev, Mode = mode, Color = color, Speed = speed, Count = count };
            var preview = new Wpf.Ui.Controls.Button { Content = L.S("Led_Preview"), MinWidth = 96 };
            preview.Click += (_, _) => { var fx = row.Read(); Shell.I.Run(() => Shell.I.Ops.LedPreview(fx), refreshStatus: false); };

            var controls = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            controls.Children.Add(mode); controls.Children.Add(color); controls.Children.Add(speed); controls.Children.Add(count); controls.Children.Add(preview);

            var header = new StackPanel { VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 16, 0) };
            header.Children.Add(new System.Windows.Controls.TextBlock { Text = L.S("Led_Ev_" + ev), Style = (Style)FindResource("CardTitle") });
            header.Children.Add(new System.Windows.Controls.TextBlock { Text = L.S("Led_Ev_" + ev + "_Desc"), Style = (Style)FindResource("CardDesc") });

            var icon = new SymbolIcon { Symbol = Icons[ev], FontSize = 24, Margin = new Thickness(0, 0, 16, 0), VerticalAlignment = VerticalAlignment.Center };

            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            Grid.SetColumn(icon, 0); Grid.SetColumn(header, 1);
            grid.Children.Add(icon); grid.Children.Add(header); grid.Children.Add(controls);

            var card = new Card { Content = grid, Margin = new Thickness(0, 0, 0, 4), Padding = new Thickness(16, 12, 16, 12) };
            EffectCards.Children.Add(card);
            _layout.Add((grid, controls, header, card));
            row.Write(new LedFx(4, 1, 0, 0));
            _rows.Add(row);
        }
        EffectCards.SizeChanged += (_, _) => Relayout();
        Relayout();
    }

    /// <summary>Width the one-line layout needs: widest control panel + icon + padding + a readable title.</summary>
    double WideNeed()
    {
        double controls = 0;
        foreach (var (_, c, _, _) in _layout)
        {
            c.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
            controls = Math.Max(controls, c.DesiredSize.Width);
        }
        return controls + IconAndPadding + MinTitleWidth;
    }

    void Relayout()
    {
        bool wide = EffectCards.ActualWidth == 0 || EffectCards.ActualWidth >= WideNeed();
        _wide = wide;
        foreach (var (_, controls, _, _) in _layout)
        {
            if (wide) { Grid.SetRow(controls, 0); Grid.SetColumn(controls, 2); Grid.SetColumnSpan(controls, 1); controls.Margin = new Thickness(0); }
            else { Grid.SetRow(controls, 1); Grid.SetColumn(controls, 1); Grid.SetColumnSpan(controls, 2); controls.Margin = new Thickness(0, 10, 0, 0); }
        }
    }

    /// <summary>Smoke test: every control panel must fit inside its card.</summary>
    public void SelfCheck()
    {
        double need = WideNeed();
        if (EffectCards.ActualWidth >= need != _wide)
            throw new InvalidOperationException($"layout mode is stale: list {EffectCards.ActualWidth:F0}, needs {need:F0}, wide={_wide}");
        foreach (var (_, controls, header, card) in _layout)
        {
            var right = controls.TransformToAncestor(card).Transform(new Point(controls.ActualWidth, 0)).X;
            if (controls.ActualWidth <= 0 || right > card.ActualWidth + 1)
                throw new InvalidOperationException($"LED row overflows its card: controls end at {right:F0}, card width {card.ActualWidth:F0}");
            if (header.ActualWidth < 80) throw new InvalidOperationException($"LED row title squeezed to {header.ActualWidth:F0}px");
        }
        App.SmokeLog($"led rows ok, list width {EffectCards.ActualWidth:F0}, one-line needs {need:F0}, wide={_wide}");
    }

    void ApplyProto(string? proto)
    {
        _proto = proto;
        ProtoText.Text = proto switch { "3C" => L.S("Led_Proto3C"), "35" => L.S("Led_Proto35"), _ => L.S("Led_ProtoNone") };
        // Only the 0x35 command has a speed parameter.
        foreach (var r in _rows) r.Speed.Visibility = proto == "35" ? Visibility.Visible : Visibility.Collapsed;
        Relayout();
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
