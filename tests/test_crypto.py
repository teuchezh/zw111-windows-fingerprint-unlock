import hashlib, hmac, subprocess, sys
out = dict(l.split() for l in subprocess.check_output([sys.argv[1]], text=True).splitlines())
kauth = bytes(range(32)); kdev = bytes(0x80+i for i in range(32)); kpc = bytes(0x40^i for i in range(32)); nonce = bytes(0xF0|i for i in range(16))
exp = {
 "sha_empty": hashlib.sha256(b"").hexdigest(),
 "sha_abc": hashlib.sha256(b"abc").hexdigest(),
 "sha_1000a": hashlib.sha256(b"a"*1000).hexdigest(),
 "host_proof": hmac.new(kauth, b"zwcp-host-v1"+nonce, hashlib.sha256).hexdigest(),
 "wrap_mask": hmac.new(kauth, b"zwcp-wrap-v1"+nonce, hashlib.sha256).hexdigest(),
 "pw_key": hashlib.sha256(b"zwcp-key-v1"+kdev+kpc).hexdigest(),
}
bad = [k for k in exp if out.get(k) != exp[k]]
print("FAIL", bad) if bad else print("ALL OK", len(exp), "vectors")
sys.exit(1 if bad else 0)
