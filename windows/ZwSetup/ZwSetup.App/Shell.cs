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
    /// <summary>Raised (on the UI thread) after a COM port appeared or disappeared and the status was refreshed.</summary>
    public event Action? DeviceChanged;
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

    System.Windows.Threading.DispatcherTimer? _debounce;
    /// <summary>Called from the window's WM_DEVICECHANGE hook; waits for the port to settle, then refreshes.</summary>
    public void OnDevicesChanged()
    {
        _debounce ??= new System.Windows.Threading.DispatcherTimer(TimeSpan.FromMilliseconds(1500), System.Windows.Threading.DispatcherPriority.Background, (_, _) =>
        {
            _debounce!.Stop();
            if (Busy) { _debounce.Start(); return; }      // an operation owns the port: try again later
            Log(L.S("DeviceListChanged"));
            RefreshStatus();
            Task.Run(async () => { await Task.Delay(300); while (Busy) await Task.Delay(200); Ui.Invoke(() => DeviceChanged?.Invoke()); });
        }, Ui);
        _debounce.Stop(); _debounce.Start();
    }
}
