using System.Windows;
using Wpf.Ui.Appearance;
using ZwSetup.App.Pages;
using ZwSetup.Core;

namespace ZwSetup.App;

public partial class MainWindow
{
    public MainWindow()
    {
        InitializeComponent();
        if (App.LoadThemeSetting() == "auto") SystemThemeWatcher.Watch(this);
        Shell.I.LogLine += line => StatusLine.Text = line;
        Shell.I.BusyChanged += busy =>
        {
            BusyRing.Visibility = busy ? Visibility.Visible : Visibility.Collapsed;
            Nav.IsEnabled = !busy;
        };
        Loaded += (_, _) =>
        {
            Nav.Navigate(typeof(StatusPage));
            Shell.I.Log(L.S("Intro"));
            if (!Win.IsAdministrator()) Shell.I.Log(L.S("NotAdmin"));
            Shell.I.RefreshStatus();
            if (App.Smoke) { Width = 900; Height = 700; RunSmoke(); }
        };
    }

    /// <summary>--smoke: visit every page in both languages and themes, then exit 0.</summary>
    /// <summary>Every CardControl on the current page must render its Header (i.e. it got the WPF-UI template).</summary>
    void CheckCards()
    {
        int cards = 0;
        void Walk(DependencyObject d)
        {
            if (d is Wpf.Ui.Controls.CardControl c)
            {
                cards++;
                if (c.Template == null || c.Header is FrameworkElement h && !h.IsVisible)
                    throw new InvalidOperationException("CardControl without template/header");
            }
            for (int i = 0; i < System.Windows.Media.VisualTreeHelper.GetChildrenCount(d); i++) Walk(System.Windows.Media.VisualTreeHelper.GetChild(d, i));
        }
        Walk(this);
        if (cards == 0) throw new InvalidOperationException("no CardControl found on the Status page");
        App.SmokeLog("cards ok: " + cards);
    }

    System.Windows.Controls.Page? FindPage()
    {
        System.Windows.Controls.Page? found = null;
        void Walk(DependencyObject d)
        {
            if (found != null) return;
            if (d is System.Windows.Controls.Page pg) { found = pg; return; }
            for (int i = 0; i < System.Windows.Media.VisualTreeHelper.GetChildrenCount(d); i++) Walk(System.Windows.Media.VisualTreeHelper.GetChild(d, i));
        }
        Walk(this);
        return found;
    }

    /// <summary>The ScrollViewer that actually scrolls the current page (WPF-UI's DynamicScrollViewer around it).</summary>
    System.Windows.Controls.ScrollViewer? FindScroll()
    {
        DependencyObject? d = FindPage();
        while (d != null && d is not System.Windows.Controls.ScrollViewer) d = System.Windows.Media.VisualTreeHelper.GetParent(d);
        return d as System.Windows.Controls.ScrollViewer;
    }

    /// <summary>Wheel over a card title must scroll the page; the scroll area must end above the status bar and reach the end.</summary>
    void CheckScroll()
    {
        var sv = FindScroll() ?? throw new InvalidOperationException("no ScrollViewer around the page");
        var svBottom = sv.TransformToAncestor(this).Transform(new Point(0, sv.ActualHeight)).Y;
        var statusTop = StatusLine.TransformToAncestor(this).Transform(new Point(0, 0)).Y;
        App.SmokeLog($"window {ActualWidth}x{ActualHeight}; status top {statusTop:F0}; scroll {sv.GetType().Name}: actual {sv.ActualHeight:F0}, viewport {sv.ViewportHeight:F0}, extent {sv.ExtentHeight:F0}, scrollable {sv.ScrollableHeight:F0}, bottom {svBottom:F0}");
        if (svBottom > statusTop + 1) throw new InvalidOperationException($"scroll area ends at {svBottom:F0}, below the status bar at {statusTop:F0}");
        if (sv.ScrollableHeight <= 0) throw new InvalidOperationException("the Setup page does not scroll at 900x700");
        App.SmokeLog("offset before wheel " + sv.VerticalOffset.ToString("F0"));
    }

    void WheelOverPage()
    {
        var sv = FindScroll() ?? throw new InvalidOperationException("no ScrollViewer around the page");
        sv.ScrollToTop();
        sv.UpdateLayout();
        // Raise the wheel on an element deep inside the page, like a real mouse over a card.
        UIElement? target = null;
        void Walk(DependencyObject d)
        {
            if (target != null) return;
            if (d is System.Windows.Controls.TextBlock tb && tb.IsVisible && tb.Parent is System.Windows.Controls.StackPanel) { target = tb; return; }
            for (int i = 0; i < System.Windows.Media.VisualTreeHelper.GetChildrenCount(d); i++) Walk(System.Windows.Media.VisualTreeHelper.GetChild(d, i));
        }
        Walk(FindPage()!);
        if (target == null) throw new InvalidOperationException("no TextBlock to wheel over");
        for (int i = 0; i < 5; i++)
            target.RaiseEvent(new System.Windows.Input.MouseWheelEventArgs(System.Windows.Input.Mouse.PrimaryDevice, Environment.TickCount, -120) { RoutedEvent = UIElement.MouseWheelEvent });
    }

    void CheckWheeled()
    {
        var sv = FindScroll()!;
        App.SmokeLog("offset after wheel " + sv.VerticalOffset.ToString("F0"));
        if (sv.VerticalOffset <= 0) throw new InvalidOperationException("mouse wheel over the page did not scroll it");
        sv.ScrollToEnd(); sv.UpdateLayout();
        if (sv.VerticalOffset + sv.ViewportHeight < sv.ExtentHeight - 1) throw new InvalidOperationException("ScrollToEnd did not reach the end");
        App.SmokeLog("scroll ok");
    }

    void RunSmoke()
    {
        App.SmokeLog("window loaded");
        var pages = new[] { typeof(StatusPage), typeof(SetupPage), typeof(FingersPage), typeof(LedPage), typeof(LogPage), typeof(SettingsPage) };
        var steps = new Queue<(string name, Action run)>();
        foreach (var lang in new[] { "ru", "en" })
        {
            steps.Enqueue(("lang " + lang, () => L.Apply(lang)));
            // Navigate returns false when the page is already current, so only exceptions count as failures.
            foreach (var p in pages) steps.Enqueue(("page " + p.Name, () => Nav.Navigate(p)));
        }
        steps.Enqueue(("page StatusPage (cards)", () => Nav.Navigate(typeof(StatusPage))));
        steps.Enqueue(("check cards", CheckCards));
        steps.Enqueue(("page SetupPage (scroll)", () => Nav.Navigate(typeof(SetupPage))));
        steps.Enqueue(("check scroll", CheckScroll));
        steps.Enqueue(("wheel", WheelOverPage));
        steps.Enqueue(("check wheel", CheckWheeled));
        steps.Enqueue(("theme light", () => App.ApplyTheme("light")));
        steps.Enqueue(("page StatusPage", () => Nav.Navigate(typeof(StatusPage))));
        steps.Enqueue(("theme dark", () => App.ApplyTheme("dark")));
        steps.Enqueue(("dialog", () => { _ = Dialogs.ShowAsync("smoke", "smoke dialog", "OK", "Cancel"); }));
        steps.Enqueue(("check dialog", () =>
        {
            var d = Dialogs.Current ?? throw new InvalidOperationException("ContentDialog did not open");
            if (!d.IsVisible || d.ActualHeight <= 0) throw new InvalidOperationException("ContentDialog is not visible");
            App.SmokeLog($"dialog {d.ActualWidth:F0}x{d.ActualHeight:F0}");
            d.Hide();
        }));
        var timer = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromMilliseconds(400) };
        timer.Tick += (_, _) =>
        {
            foreach (Window w in Application.Current.Windows) if (w != this && w.IsVisible) { App.SmokeLog("closing " + w.Title); w.Close(); }
            if (steps.Count == 0) { timer.Stop(); App.SmokeExit(0, "smoke ok"); return; }
            var (name, run) = steps.Dequeue();
            App.SmokeLog("step " + name);
            run();
        };
        timer.Start();
    }
}
