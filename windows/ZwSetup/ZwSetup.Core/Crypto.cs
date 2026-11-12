using System.Security.Cryptography;
using System.Text;

namespace ZwSetup.Core;

/// <summary>Key schedule shared with the firmware and the C++ provider (see windows/common/sha256.h).</summary>
public static class Crypto
{
    static readonly byte[] HostLabel = Encoding.ASCII.GetBytes("zwcp-host-v1");
    static readonly byte[] WrapLabel = Encoding.ASCII.GetBytes("zwcp-wrap-v1");
    static readonly byte[] KeyLabel  = Encoding.ASCII.GetBytes("zwcp-key-v1");
    static readonly byte[] PwAad     = Encoding.ASCII.GetBytes("zwcp-pw-v1");

    public static byte[] Random(int n) => RandomNumberGenerator.GetBytes(n);

    public static byte[] HostProof(byte[] kauth, byte[] nonce) => Hmac(kauth, HostLabel, nonce);
    public static byte[] WrapMask(byte[] kauth, byte[] nonce) => Hmac(kauth, WrapLabel, nonce);

    public static byte[] DerivePasswordKey(byte[] kdev, byte[] kpc)
    {
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        sha.AppendData(KeyLabel); sha.AppendData(kdev); sha.AppendData(kpc);
        return sha.GetHashAndReset();
    }

    static byte[] Hmac(byte[] key, byte[] a, byte[] b)
    {
        using var h = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, key);
        h.AppendData(a); h.AppendData(b);
        return h.GetHashAndReset();
    }

    /// <summary>AES-256-GCM of the password as UTF-16LE (no terminator), AAD "zwcp-pw-v1".</summary>
    public static void SealPassword(Secrets s, byte[] kdev, string password)
    {
        var key = DerivePasswordKey(kdev, s.Kpc);
        try
        {
            s.Iv = Random(12);
            var plain = Encoding.Unicode.GetBytes(password);
            s.Ct = new byte[plain.Length]; s.Tag = new byte[16];
            using var gcm = new AesGcm(key, 16);
            gcm.Encrypt(s.Iv, plain, s.Ct, s.Tag, PwAad);
            CryptographicOperations.ZeroMemory(plain);
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    public static string? OpenPassword(Secrets s, byte[] kdev)
    {
        var key = DerivePasswordKey(kdev, s.Kpc);
        try
        {
            var plain = new byte[s.Ct.Length];
            using var gcm = new AesGcm(key, 16);
            try { gcm.Decrypt(s.Iv, s.Ct, s.Tag, plain, PwAad); }
            catch (CryptographicException) { return null; }
            var pw = Encoding.Unicode.GetString(plain);
            CryptographicOperations.ZeroMemory(plain);
            return pw;
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    public static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
    public static byte[]? UnHex(string s, int expectedLen)
    {
        if (s.Length != expectedLen * 2) return null;
        try { return Convert.FromHexString(s); } catch (FormatException) { return null; }
    }
}

/// <summary>The PC-side secret material, stored DPAPI-protected in the registry (same layout as the C++ tools).</summary>
public sealed class Secrets : IDisposable
{
    const uint Magic = 0x3153575A; // "ZWS1"
    public byte[] Kpc = new byte[32];
    public byte[] Kauth = new byte[32];
    public byte[] Iv = new byte[12];
    public byte[] Tag = new byte[16];
    public byte[] Ct = Array.Empty<byte>();

    public byte[] Pack()
    {
        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);
        w.Write(Magic); w.Write(Kpc); w.Write(Kauth); w.Write(Iv); w.Write(Tag); w.Write((uint)Ct.Length); w.Write(Ct);
        return ms.ToArray();
    }

    public static Secrets? Unpack(byte[] raw)
    {
        if (raw.Length < 4 + 32 + 32 + 12 + 16 + 4) return null;
        using var r = new BinaryReader(new MemoryStream(raw));
        if (r.ReadUInt32() != Magic) return null;
        var s = new Secrets { Kpc = r.ReadBytes(32), Kauth = r.ReadBytes(32), Iv = r.ReadBytes(12), Tag = r.ReadBytes(16) };
        uint len = r.ReadUInt32();
        if (raw.Length != 4 + 32 + 32 + 12 + 16 + 4 + len) return null;
        s.Ct = r.ReadBytes((int)len);
        return s;
    }

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(Kpc); CryptographicOperations.ZeroMemory(Kauth); CryptographicOperations.ZeroMemory(Ct);
    }
}
