// Prints the same test vectors as tests/test_crypto.cpp so tests/test_crypto.py can verify the C# port.
using ZwSetup.Core;
using System.Security.Cryptography;
using System.Text;

byte[] kauth = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
byte[] kdev = Enumerable.Range(0, 32).Select(i => (byte)(0x80 + i)).ToArray();
byte[] kpc = Enumerable.Range(0, 32).Select(i => (byte)(0x40 ^ i)).ToArray();
byte[] nonce = Enumerable.Range(0, 16).Select(i => (byte)(0xF0 | i)).ToArray();
Console.WriteLine("sha_empty " + Convert.ToHexString(SHA256.HashData(Array.Empty<byte>())).ToLower());
Console.WriteLine("sha_abc " + Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes("abc"))).ToLower());
Console.WriteLine("sha_1000a " + Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(new string('a', 1000)))).ToLower());
Console.WriteLine("host_proof " + Crypto.Hex(Crypto.HostProof(kauth, nonce)));
Console.WriteLine("wrap_mask " + Crypto.Hex(Crypto.WrapMask(kauth, nonce)));
Console.WriteLine("pw_key " + Crypto.Hex(Crypto.DerivePasswordKey(kdev, kpc)));
// Round trips that do not need Windows: seal/open, pack/unpack.
var s = new Secrets { Kpc = kpc, Kauth = kauth };
Crypto.SealPassword(s, kdev, "Пароль-Test123");
var back = Secrets.Unpack(s.Pack()) ?? throw new Exception("unpack failed");
if (Crypto.OpenPassword(back, kdev) != "Пароль-Test123") throw new Exception("seal/open mismatch");
var wrongKdev = (byte[])kdev.Clone(); wrongKdev[0] ^= 1;
if (Crypto.OpenPassword(back, wrongKdev) != null) throw new Exception("wrong key accepted");
Console.Error.WriteLine("roundtrip ok, " + L.S("AppTitle"));
