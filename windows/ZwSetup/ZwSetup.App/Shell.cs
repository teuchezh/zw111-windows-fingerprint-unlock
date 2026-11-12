using System.Text;
using System.Windows;
using System.Windows.Threading;
using ZwSetup.Core;

namespace ZwSetup.App;

/// <summary>Glue between the UI and <see cref="Ops"/>: runs operations on a worker thread, routes log lines,
/// confirmations and errors to the UI thread.</summary>
public sealed class Shell
{
    public static readonly Shell I = new();
    public readonly Ops Ops = new();
    public readonly StringBuilder LogText = new();
    public event Action<string>? LogLine;
    public event Action<bool>? BusyChanged;
    public event Action? StatusChanged;
    public bool Busy { get; private set; }
    public Ops.StatusInfo? LastStatus { get; private set; }

    Dispatcher Ui => Application.Current.Dispatcher;

    Shell()
    {
        Ops.Log = Log;
        Ops.Error = msg => { Log(L.S("Dlg_Error") + ": " + msg); Dialogs.Error(msg); };
        Ops.Ask = msg => Dialogs.Confirm(msg);
    }

    public void Log(string line)
    {
        var stamped = DateTime.Now.ToString("HH:mm:ss") + "  " + line;
        Ui.BeginInvoke(() => { LogText.AppendLine(stamped); LogLine?.Invoke(stamped); });
    }

    /// <summary>Runs <paramref name="op"/> on a worker thread; refreshes the status afterwards when requested.</summary>
    public void Run(Func<bool> op, bool refreshStatus = true)
    {
        if (Busy) return;
        SetBusy(true);
        Task.Run(() =>
        {
            try { op(); }
            catch (Exception e) { Log("EXCEPTION: " + e); Dialogs.Error(e.Message); }
            if (refreshStatus) RefreshStatusCore();
            Ui.Invoke(() => SetBusy(false));
        });
    }

    public void RefreshStatus(string? port = null, string? usb = null)
    {
        if (Busy) return;
        SetBusy(true);
        Task.Run(() => { RefreshStatusCore(port, usb); Ui.Invoke(() => SetBusy(false)); });
    }

    void RefreshStatusCore(string? port = null, string? usb = null)
    {
        try { LastStatus = Ops.Status(port, usb); }
        catch (Exception e) { Log("EXCEPTION: " + e.Message); }
        Ui.Invoke(() => StatusChanged?.Invoke());
    }

    void SetBusy(bool b) { Busy = b; BusyChanged?.Invoke(b); }
}
