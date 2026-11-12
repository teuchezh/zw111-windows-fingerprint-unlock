// Portable SHA-256 and HMAC-SHA256. Header-only, no dependencies.
// Shared verbatim between the RP2040 firmware and the Windows side.
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>

namespace zw {

struct Sha256 {
    uint32_t h[8];
    uint8_t  buf[64];
    uint64_t total;
    size_t   used;

    static inline uint32_t ror(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

    void init() {
        static const uint32_t iv[8] = {
            0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
            0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u };
        memcpy(h, iv, sizeof(h));
        total = 0; used = 0;
    }

    void block(const uint8_t* p) {
        static const uint32_t k[64] = {
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };
        uint32_t w[64];
        for (int i = 0; i < 16; i++)
            w[i] = ((uint32_t)p[4*i] << 24) | ((uint32_t)p[4*i+1] << 16) | ((uint32_t)p[4*i+2] << 8) | p[4*i+3];
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = ror(w[i-15], 7) ^ ror(w[i-15], 18) ^ (w[i-15] >> 3);
            uint32_t s1 = ror(w[i-2], 17) ^ ror(w[i-2], 19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = ror(e,6) ^ ror(e,11) ^ ror(e,25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = hh + S1 + ch + k[i] + w[i];
            uint32_t S0 = ror(a,2) ^ ror(a,13) ^ ror(a,22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + maj;
            hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }

    void update(const void* data, size_t len) {
        const uint8_t* p = (const uint8_t*)data;
        total += len;
        while (len > 0) {
            size_t n = 64 - used;
            if (n > len) n = len;
            memcpy(buf + used, p, n);
            used += n; p += n; len -= n;
            if (used == 64) { block(buf); used = 0; }
        }
    }

    void finish(uint8_t out[32]) {
        uint64_t bits = total * 8;
        uint8_t pad = 0x80;
        update(&pad, 1);
        uint8_t z = 0;
        while (used != 56) update(&z, 1);
        uint8_t lenb[8];
        for (int i = 0; i < 8; i++) lenb[i] = (uint8_t)(bits >> (56 - 8*i));
        update(lenb, 8);
        for (int i = 0; i < 8; i++) {
            out[4*i]   = (uint8_t)(h[i] >> 24);
            out[4*i+1] = (uint8_t)(h[i] >> 16);
            out[4*i+2] = (uint8_t)(h[i] >> 8);
            out[4*i+3] = (uint8_t)(h[i]);
        }
        memset(buf, 0, sizeof(buf));
    }
};

inline void sha256(const void* data, size_t len, uint8_t out[32]) {
    Sha256 s; s.init(); s.update(data, len); s.finish(out);
}

// HMAC-SHA256 with a 32-byte key (all keys in this project are 32 bytes).
struct HmacSha256 {
    Sha256 inner;
    uint8_t okey[64];

    void init(const uint8_t key[32]) {
        uint8_t ikey[64];
        memset(ikey, 0x36, 64); memset(okey, 0x5c, 64);
        for (int i = 0; i < 32; i++) { ikey[i] ^= key[i]; okey[i] ^= key[i]; }
        inner.init(); inner.update(ikey, 64);
        memset(ikey, 0, sizeof(ikey));
    }
    void update(const void* data, size_t len) { inner.update(data, len); }
    void finish(uint8_t out[32]) {
        uint8_t ih[32];
        inner.finish(ih);
        Sha256 o; o.init(); o.update(okey, 64); o.update(ih, 32); o.finish(out);
        memset(okey, 0, sizeof(okey)); memset(ih, 0, sizeof(ih));
    }
};

inline void hmac_sha256(const uint8_t key[32], const void* d1, size_t l1, const void* d2, size_t l2, uint8_t out[32]) {
    HmacSha256 h; h.init(key);
    if (l1) h.update(d1, l1);
    if (l2) h.update(d2, l2);
    h.finish(out);
}

// Constant-time comparison.
inline bool ct_equal(const uint8_t* a, const uint8_t* b, size_t n) {
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++) d |= (uint8_t)(a[i] ^ b[i]);
    return d == 0;
}

// Hex helpers.
inline int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
inline bool hex2bin(const char* hex, uint8_t* out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        int hi = hexval(hex[2*i]), lo = hexval(hex[2*i+1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return hex[2*n] == 0 || hex[2*n] == ' ' || hex[2*n] == '\r' || hex[2*n] == '\n';
}
inline void bin2hex(const uint8_t* in, size_t n, char* out) {
    static const char* d = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[2*i] = d[in[i] >> 4]; out[2*i+1] = d[in[i] & 15]; }
    out[2*n] = 0;
}

// ---- Protocol constants shared by both sides ----
// Host proof:        HMAC(K_auth, "zwcp-host-v1" || nonce16)
// K_dev wrapping:    E = K_dev XOR HMAC(K_auth, "zwcp-wrap-v1" || nonce16)
// Password key:      K = SHA256("zwcp-key-v1" || K_dev || K_pc)
static const char* const kHostLabel = "zwcp-host-v1";
static const char* const kWrapLabel = "zwcp-wrap-v1";
static const char* const kKeyLabel  = "zwcp-key-v1";

inline void host_proof(const uint8_t kauth[32], const uint8_t nonce[16], uint8_t out[32]) {
    hmac_sha256(kauth, kHostLabel, strlen(kHostLabel), nonce, 16, out);
}
inline void wrap_mask(const uint8_t kauth[32], const uint8_t nonce[16], uint8_t out[32]) {
    hmac_sha256(kauth, kWrapLabel, strlen(kWrapLabel), nonce, 16, out);
}
inline void derive_password_key(const uint8_t kdev[32], const uint8_t kpc[32], uint8_t out[32]) {
    Sha256 s; s.init();
    s.update(kKeyLabel, strlen(kKeyLabel));
    s.update(kdev, 32); s.update(kpc, 32);
    s.finish(out);
}

} // namespace zw
