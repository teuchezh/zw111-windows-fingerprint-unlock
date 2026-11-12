using System.Windows;
using System.Windows.Controls;
using ZwSetup.Core;

namespace ZwSetup.App.Pages;

public partial class SetupPage : Page
{
    // Field values survive navigation between pages within the session.
    static string? _user, _domain, _port, _usb, _finger;

    public SetupPage()
    {
        InitializeComponent();
        Loaded += (_, _) => Fill();
        Unloaded += (_, _) => { _user = UserBox.Text; _domain = DomainBox.Text; _port = PortBox.Text; _usb = UsbBox.Text; _finger = FingerBox.Text; };
    }

    void Fill()
    {
        if (_user != null) { UserBox.Text = _user; DomainBox.Text = _domain; PortBox.Text = _port; UsbBox.Text = _usb; FingerBox.Text = _finger; return; }
        var cfg = Config.Load(out bool exists);
        if (exists && cfg.User.Length > 0)
        {
            UserBox.Text = cfg.User; DomainBox.Text = cfg.Domain; FingerBox.Text = cfg.FingerId.ToString();
        }
        else
        {
            var me = Environment.UserName;
            if (Win.LinkedMicrosoftAccount(me, out var email)) { UserBox.Text = email; DomainBox.Text = "MicrosoftAccount"; Shell.I.Log(L.S("Setup_MsaDetected")); }
            else { UserBox.Text = me; DomainBox.Text = "."; }
        }
        PortBox.Text = cfg.Port; UsbBox.Text = cfg.UsbId;
    }

    Ops.SetupInput Input() => new(UserBox.Text, DomainBox.Text, PassBox.Password, Pass2Box.Password, PortBox.Text, UsbBox.Text,
                                  int.TryParse(FingerBox.Text, out var f) ? f : 0, Config.Load(out _).Debug);

    void Provision_Click(object sender, RoutedEventArgs e)
    {
        var inp = Input();
        Shell.I.Run(() => Shell.I.Ops.Provision(inp));
        PassBox.Password = ""; Pass2Box.Password = "";
    }

    void Test_Click(object sender, RoutedEventArgs e)
    {
        string port = PortBox.Text, usb = UsbBox.Text;
        Shell.I.Run(() => Shell.I.Ops.Test(port, usb), refreshStatus: false);
    }

    void ChangePw_Click(object sender, RoutedEventArgs e)
    {
        string pw = PassBox.Password, pw2 = Pass2Box.Password, port = PortBox.Text, usb = UsbBox.Text;
        Shell.I.Run(() => Shell.I.Ops.SetPassword(pw, pw2, port, usb), refreshStatus: false);
        PassBox.Password = ""; Pass2Box.Password = "";
    }
}
