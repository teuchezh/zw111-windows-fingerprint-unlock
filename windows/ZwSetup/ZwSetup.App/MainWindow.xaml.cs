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
            if (App.Smoke) RunSmoke();
        };
    }

    /// <summary>--smoke: visit every page in both languages and themes, then exit 0.</summary>
    void RunSmoke()
    {
        var pages = new[] { typeof(StatusPage), typeof(SetupPage), typeof(FingersPage), typeof(LogPage), typeof(SettingsPage) };
        var steps = new Queue<Action>();
        foreach (var lang in new[] { "ru", "en" })
        {
            steps.Enqueue(() => L.Apply(lang));
            foreach (var p in pages) steps.Enqueue(() => { if (!Nav.Navigate(p)) throw new InvalidOperationException("Navigate failed: " + p.Name); });
        }
        steps.Enqueue(() => App.ApplyTheme("light"));
        steps.Enqueue(() => Nav.Navigate(typeof(StatusPage)));
        steps.Enqueue(() => App.ApplyTheme("dark"));
        steps.Enqueue(() => Dialogs.Error("smoke"));   // closed by the timer below
        var timer = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromMilliseconds(400) };
        timer.Tick += (_, _) =>
        {
            // Close any modal dialog left open by the previous step.
            foreach (Window w in Application.Current.Windows) if (w != this && w.IsVisible) w.Close();
            if (steps.Count == 0) { timer.Stop(); Console.WriteLine("smoke ok"); Application.Current.Shutdown(0); return; }
            steps.Dequeue()();
        };
        timer.Start();
    }
}
