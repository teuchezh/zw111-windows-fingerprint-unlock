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

    System.Windows.Controls.ScrollViewer? FindScroll()
    {
        System.Windows.Controls.ScrollViewer? found = null;
        void Walk(DependencyObject d)
        {
            if (found != null) return;
            if (d is System.Windows.Controls.Page pg && pg.Content is System.Windows.Controls.ScrollViewer sv) { found = sv; return; }
            for (int i = 0; i < System.Windows.Media.VisualTreeHelper.GetChildrenCount(d); i++) Walk(System.Windows.Media.VisualTreeHelper.GetChild(d, i));
        }
        Walk(this);
        return found;
    }

    /// <summary>The page scroll area must end above the status bar, and scrolling must reach the end of the content.</summary>
    void CheckScroll()
    {
        var sv = FindScroll() ?? throw new InvalidOperationException("no page ScrollViewer");
        var svBottom = sv.TransformToAncestor(this).Transform(new Point(0, sv.ActualHeight)).Y;
        var statusTop = StatusLine.TransformToAncestor(this).Transform(new Point(0, 0)).Y;
        var navBottom = Nav.TransformToAncestor(this).Transform(new Point(0, Nav.ActualHeight)).Y;
        App.SmokeLog($"window {ActualWidth}x{ActualHeight}; nav bottom {navBottom:F0}; status top {statusTop:F0}; " +
                     $"scroll: actual {sv.ActualHeight:F0}, viewport {sv.ViewportHeight:F0}, extent {sv.ExtentHeight:F0}, offset {sv.VerticalOffset:F0}, scrollable {sv.ScrollableHeight:F0}, bottom {svBottom:F0}");
        if (svBottom > statusTop + 1) throw new InvalidOperationException($"page scroll area ends at {svBottom:F0}, below the status bar at {statusTop:F0}");
        if (sv.ExtentHeight > sv.ViewportHeight + 1 && sv.VerticalOffset + sv.ViewportHeight < sv.ExtentHeight - 1)
            throw new InvalidOperationException("ScrollToEnd did not reach the end");
    }

    void RunSmoke()
    {
        App.SmokeLog("window loaded");
        var pages = new[] { typeof(StatusPage), typeof(SetupPage), typeof(FingersPage), typeof(LogPage), typeof(SettingsPage) };
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
        steps.Enqueue(("scroll to end", () => { var sv = FindScroll(); sv?.ScrollToEnd(); }));
        steps.Enqueue(("check scroll", CheckScroll));
        steps.Enqueue(("theme light", () => App.ApplyTheme("light")));
        steps.Enqueue(("page StatusPage", () => Nav.Navigate(typeof(StatusPage))));
        steps.Enqueue(("theme dark", () => App.ApplyTheme("dark")));
        steps.Enqueue(("dialog", () =>
        {
            // Open a dialog non-modally so the step returns; the next tick closes it.
            var d = new Wpf.Ui.Controls.FluentWindow { Title = "smoke", Width = 300, Height = 150, Owner = this, Content = new System.Windows.Controls.TextBlock { Text = "smoke" } };
            d.Show();
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
