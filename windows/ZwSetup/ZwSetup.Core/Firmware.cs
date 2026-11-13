using System.Reflection;
using System.Text;

namespace ZwSetup.Core;

/// <summary>UF2 images bundled into the app by CI, and the RP2040 update procedure.</summary>
public static class Firmware
{
    const uint Uf2Magic0 = 0x0A324655, Uf2Magic1 = 0x9E5D5157, Rp2040Family = 0xE48BFF56;

    /// <summary>Bundled image for a board ("yd_rp2040", "pico"), or null. version.txt holds the version.</summary>
    public static byte[]? Bundled(string board, Assembly asm)
    {
        var name = asm.GetManifestResourceNames().FirstOrDefault(n => n.EndsWith($"firmware-{board}.uf2", StringComparison.OrdinalIgnoreCase));
        if (name == null) return null;
        using var s = asm.GetManifestResourceStream(name)!;
        using var ms = new MemoryStream(); s.CopyTo(ms); return ms.ToArray();
    }

    public static string? BundledVersion(Assembly asm)
    {
        var name = asm.GetManifestResourceNames().FirstOrDefault(n => n.EndsWith("firmware-version.txt", StringComparison.OrdinalIgnoreCase));
        if (name == null) return null;
        using var r = new StreamReader(asm.GetManifestResourceStream(name)!);
        return r.ReadToEnd().Trim();
    }

    /// <summary>Checks the UF2 block magic and that the image targets the RP2040.</summary>
    public static bool IsRp2040Uf2(byte[] img, out string why)
    {
        why = "";
        if (img.Length < 512 || img.Length % 512 != 0) { why = "not a UF2 file"; return false; }
        uint m0 = BitConverter.ToUInt32(img, 0), m1 = BitConverter.ToUInt32(img, 4), flags = BitConverter.ToUInt32(img, 8), fam = BitConverter.ToUInt32(img, 28);
        if (m0 != Uf2Magic0 || m1 != Uf2Magic1) { why = "not a UF2 file"; return false; }
        if ((flags & 0x2000) != 0 && fam != Rp2040Family) { why = $"UF2 for another chip (family 0x{fam:X8})"; return false; }
        return true;
    }

    /// <summary>Board name from the USB id when the firmware cannot tell (pre-1.1): VCC-GND YD-RP2040 enumerates as PID 800A.</summary>
    public static string GuessBoard(string hardwareId) =>
        hardwareId.Contains("PID_800A", StringComparison.OrdinalIgnoreCase) ? "yd_rp2040" : "pico";

    /// <summary>Waits for the RPI-RP2 mass-storage drive the bootloader exposes.</summary>
    public static string? WaitForBootDrive(TimeSpan timeout, CancellationToken cancel = default)
    {
        var until = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < until && !cancel.IsCancellationRequested)
        {
            foreach (var d in DriveInfo.GetDrives())
            {
                try
                {
                    if (!d.IsReady || d.DriveType != DriveType.Removable) continue;
                    var info = Path.Combine(d.RootDirectory.FullName, "INFO_UF2.TXT");
                    if (File.Exists(info) && File.ReadAllText(info, Encoding.ASCII).Contains("RP2", StringComparison.OrdinalIgnoreCase))
                        return d.RootDirectory.FullName;
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
            Thread.Sleep(500);
        }
        return null;
    }

    /// <summary>Copies the image; the drive disappears as soon as the board reboots, which may surface as an IOException.</summary>
    public static bool CopyToBootDrive(string root, byte[] img, out string err)
    {
        err = "";
        try
        {
            using var f = new FileStream(Path.Combine(root, "firmware.uf2"), FileMode.Create, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough);
            f.Write(img, 0, img.Length);
            f.Flush(true);
            return true;
        }
        catch (IOException e) when (e.HResult is unchecked((int)0x80070015) or unchecked((int)0x8007048F) or unchecked((int)0x80070037))
        {
            return true;   // device not ready / disconnected right after the last block: the board is rebooting
        }
        catch (Exception e) { err = e.Message; return false; }
    }
}
