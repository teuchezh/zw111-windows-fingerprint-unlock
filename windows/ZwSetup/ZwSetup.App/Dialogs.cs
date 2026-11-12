using System.Windows;
using System.Windows.Controls;
using Wpf.Ui.Controls;
using ZwSetup.Core;

namespace ZwSetup.App;

/// <summary>Fluent in-window dialogs (WPF-UI ContentDialog) hosted in MainWindow.DialogHost.</summary>
public static class Dialogs
{
    static ContentPresenter Host => ((MainWindow)Application.Current.MainWindow).DialogHost;

    /// <summary>The dialog currently on screen (used by the smoke test to close it).</summary>
    public static ContentDialog? Current { get; private set; }

    public static async Task<bool> ShowAsync(string title, string text, string primary, string? close)
    {
        // ContentDialog always shows its Close button and hides Primary when its text is empty,
        // so a single-button dialog uses only the Close button.
        bool single = close == null;
        var d = new ContentDialog(Host)
        {
            Title = title,
            Content = new System.Windows.Controls.TextBlock { Text = text, TextWrapping = TextWrapping.Wrap, FontSize = 14 },
            PrimaryButtonText = single ? "" : primary,
            CloseButtonText = single ? primary : close!,
            DefaultButton = single ? ContentDialogButton.Close : ContentDialogButton.Primary,
            DialogMaxWidth = 520,
        };
        Current = d;
        try { return await d.ShowAsync() == ContentDialogResult.Primary; }
        finally { Current = null; }
    }

    /// <summary>Called from a worker thread: shows the dialog on the UI thread and blocks until it closes.</summary>
    public static bool Confirm(string text) =>
        Application.Current.Dispatcher.InvokeAsync(() => ShowAsync(L.S("Dlg_Attention"), text, L.S("Dlg_Ok"), L.S("Dlg_Cancel"))).Task.Unwrap().GetAwaiter().GetResult();

    public static void Error(string text) =>
        Application.Current.Dispatcher.InvokeAsync(() => ShowAsync(L.S("Dlg_Error"), text, L.S("Dlg_Ok"), null)).Task.Unwrap().GetAwaiter().GetResult();
}
