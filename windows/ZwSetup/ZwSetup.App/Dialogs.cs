using System.Windows;
using Wpf.Ui.Controls;
using ZwSetup.Core;

namespace ZwSetup.App;

/// <summary>Small modal dialogs built on FluentWindow (synchronous ShowDialog, safe to call via Dispatcher.Invoke).</summary>
public static class Dialogs
{
    static bool Show(string title, string text, string primary, string? secondary)
    {
        var w = new FluentWindow
        {
            Title = title, Width = 460, SizeToContent = SizeToContent.Height, ResizeMode = ResizeMode.NoResize,
            WindowStartupLocation = WindowStartupLocation.CenterOwner, Owner = Application.Current.MainWindow,
            ExtendsContentIntoTitleBar = true, WindowBackdropType = WindowBackdropType.Mica, ShowInTaskbar = false,
        };
        var root = new System.Windows.Controls.StackPanel { Margin = new Thickness(0, 0, 0, 16) };
        root.Children.Add(new TitleBar { Title = title, ShowMinimize = false, ShowMaximize = false });
        root.Children.Add(new System.Windows.Controls.TextBlock
        {
            Text = text, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(24, 8, 24, 20), FontSize = 14,
        });
        var buttons = new System.Windows.Controls.StackPanel { Orientation = System.Windows.Controls.Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(24, 0, 24, 0) };
        var ok = new Wpf.Ui.Controls.Button { Content = primary, Appearance = ControlAppearance.Primary, MinWidth = 110, Margin = new Thickness(0, 0, 8, 0), IsDefault = true };
        ok.Click += (_, _) => { w.DialogResult = true; w.Close(); };
        buttons.Children.Add(ok);
        if (secondary != null)
        {
            var cancel = new Wpf.Ui.Controls.Button { Content = secondary, MinWidth = 110, IsCancel = true };
            cancel.Click += (_, _) => { w.DialogResult = false; w.Close(); };
            buttons.Children.Add(cancel);
        }
        root.Children.Add(buttons);
        w.Content = root;
        return w.ShowDialog() == true;
    }

    public static bool Confirm(string text) => Show(L.S("Dlg_Attention"), text, L.S("Dlg_Ok"), L.S("Dlg_Cancel"));
    public static void Error(string text) => Show(L.S("Dlg_Error"), text, L.S("Dlg_Ok"), null);
}
