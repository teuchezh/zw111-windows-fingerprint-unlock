using System.Windows;
using System.Windows.Controls;

namespace ZwSetup.App.Pages;

public partial class LogPage : Page
{
    public LogPage()
    {
        InitializeComponent();
        Loaded += (_, _) => { LogBox.Text = Shell.I.LogText.ToString(); LogBox.ScrollToEnd(); Shell.I.LogLine += Append; };
        Unloaded += (_, _) => Shell.I.LogLine -= Append;
    }

    void Append(string line) { LogBox.AppendText(line + Environment.NewLine); LogBox.ScrollToEnd(); }
    void Clear_Click(object sender, RoutedEventArgs e) { Shell.I.LogText.Clear(); LogBox.Clear(); }
}
