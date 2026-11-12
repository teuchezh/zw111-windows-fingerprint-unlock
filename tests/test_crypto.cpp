// Linux self-test for the shared crypto header: prints values that test_crypto.py verifies with hashlib/hmac.
#include "../windows/common/sha256.h"
#include <stdio.h>
#include <string>
using namespace zw;
static void p(const char* name, const uint8_t* b, size_t n) { char h[2*64+1]; bin2hex(b, n, h); printf("%s %s\n", name, h); }
int main() {
    uint8_t out[32];
    sha256("", 0, out); p("sha_empty", out, 32);
    sha256("abc", 3, out); p("sha_abc", out, 32);
    std::string longmsg(1000, 'a'); sha256(longmsg.data(), longmsg.size(), out); p("sha_1000a", out, 32);
    uint8_t kauth[32], kdev[32], kpc[32], nonce[16];
    for (int i = 0; i < 32; i++) { kauth[i] = i; kdev[i] = 0x80 + i; kpc[i] = 0x40 ^ i; }
    for (int i = 0; i < 16; i++) nonce[i] = 0xF0 | i;
    host_proof(kauth, nonce, out); p("host_proof", out, 32);
    wrap_mask(kauth, nonce, out); p("wrap_mask", out, 32);
    derive_password_key(kdev, kpc, out); p("pw_key", out, 32);
    // hex round trip
    uint8_t back[32]; char hx[65]; bin2hex(kdev, 32, hx);
    if (!hex2bin(hx, back, 32) || memcmp(back, kdev, 32)) { printf("HEXFAIL\n"); return 1; }
    if (hex2bin("zz", back, 1)) { printf("HEXFAIL2\n"); return 1; }
    if (!ct_equal(kdev, back, 32) || ct_equal(kdev, kpc, 32)) { printf("CTFAIL\n"); return 1; }
    return 0;
}
