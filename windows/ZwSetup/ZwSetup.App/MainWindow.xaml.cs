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
        };
    }
}
