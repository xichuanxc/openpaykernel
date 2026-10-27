/* SHA-1 (FIPS 180-4) and the RSA public-key operation via Montgomery multiplication.
 * Only public-key operations are needed by an EMV terminal, so constant-time behaviour is
 * not required here.
 * SPDX-License-Identifier: Apache-2.0 */
#include "opk_internal.h"

/* ------------------------------------------------------------------ SHA-1 */
#define ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static void sha1_block(uint32_t h[5], const uint8_t *p)
{
    uint32_t w[80], a, b, c, d, e, t;
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 | (uint32_t)p[4 * i + 2] << 8 | p[4 * i + 3];
    for (int i = 16; i < 80; i++)
        w[i] = ROL(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4];
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20)      { f = (b & c) | (~b & d);           k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d;                    k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d);  k = 0x8F1BBCDC; }
        else             { f = b ^ c ^ d;                    k = 0xCA62C1D6; }
        t = ROL(a, 5) + f + e + k + w[i];
        e = d; d = c; c = ROL(b, 30); b = a; a = t;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}

void opk_sha1_init(opk_sha1_ctx *c)
{
    static const uint32_t iv[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    memcpy(c->h, iv, sizeof iv);
    c->total = 0;
    c->buf_len = 0;
}

void opk_sha1_update(opk_sha1_ctx *c, const uint8_t *d, size_t n)
{
    c->total += n;
    while (n) {
        size_t take = 64 - c->buf_len < n ? 64 - c->buf_len : n;
        memcpy(c->buf + c->buf_len, d, take);
        c->buf_len += take;
        d += take;
        n -= take;
        if (c->buf_len == 64) {
            sha1_block(c->h, c->buf);
            c->buf_len = 0;
        }
    }
}

void opk_sha1_final(opk_sha1_ctx *c, uint8_t out[20])
{
    uint64_t bits = c->total * 8;
    uint8_t pad = 0x80, zero = 0, len[8];
    opk_sha1_update(c, &pad, 1);
    while (c->buf_len != 56)
        opk_sha1_update(c, &zero, 1);
    for (int i = 0; i < 8; i++)
        len[i] = (uint8_t)(bits >> (56 - 8 * i));
    opk_sha1_update(c, len, 8);
    for (int i = 0; i < 5; i++) {
        out[4 * i] = (uint8_t)(c->h[i] >> 24);
        out[4 * i + 1] = (uint8_t)(c->h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(c->h[i] >> 8);
        out[4 * i + 3] = (uint8_t)c->h[i];
    }
}

void opk_sha1(const uint8_t *data, size_t len, uint8_t out[20])
{
    opk_sha1_ctx c;
    opk_sha1_init(&c);
    opk_sha1_update(&c, data, len);
    opk_sha1_final(&c, out);
}

/* ------------------------------------------------------------------ bignum */
#define BN_WORDS (OPK_MAX_RSA_BYTES / 4 + 1)
typedef struct {
    uint32_t w[BN_WORDS];
} bn;

static void bn_from_bytes(bn *r, const uint8_t *b, size_t len, int words)
{
    memset(r, 0, sizeof *r);
    for (size_t i = 0; i < len; i++) {
        size_t bit = (len - 1 - i) * 8;
        r->w[bit / 32] |= (uint32_t)b[i] << (bit % 32);
    }
    (void)words;
}

static void bn_to_bytes(const bn *a, uint8_t *b, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        size_t bit = (len - 1 - i) * 8;
        b[i] = (uint8_t)(a->w[bit / 32] >> (bit % 32));
    }
}

static int bn_cmp(const bn *a, const bn *b, int k)
{
    for (int i = k - 1; i >= 0; i--)
        if (a->w[i] != b->w[i])
            return a->w[i] > b->w[i] ? 1 : -1;
    return 0;
}

static uint32_t bn_sub(bn *r, const bn *a, const bn *b, int k)
{
    uint64_t borrow = 0;
    for (int i = 0; i < k; i++) {
        uint64_t d = (uint64_t)a->w[i] - b->w[i] - borrow;
        r->w[i] = (uint32_t)d;
        borrow = (d >> 63) & 1;
    }
    return (uint32_t)borrow;
}

/* r = a*b*R^-1 mod n  (CIOS Montgomery multiplication) */
static void mont_mul(bn *r, const bn *a, const bn *b, const bn *n, uint32_t n0inv, int k)
{
    uint32_t t[BN_WORDS + 2] = {0};
    for (int i = 0; i < k; i++) {
        uint64_t c = 0;
        for (int j = 0; j < k; j++) {
            uint64_t s = (uint64_t)t[j] + (uint64_t)a->w[j] * b->w[i] + c;
            t[j] = (uint32_t)s;
            c = s >> 32;
        }
        uint64_t s = (uint64_t)t[k] + c;
        t[k] = (uint32_t)s;
        t[k + 1] = (uint32_t)(s >> 32);
        uint32_t m = t[0] * n0inv;
        s = (uint64_t)t[0] + (uint64_t)m * n->w[0];
        c = s >> 32;
        for (int j = 1; j < k; j++) {
            s = (uint64_t)t[j] + (uint64_t)m * n->w[j] + c;
            t[j - 1] = (uint32_t)s;
            c = s >> 32;
        }
        s = (uint64_t)t[k] + c;
        t[k - 1] = (uint32_t)s;
        t[k] = t[k + 1] + (uint32_t)(s >> 32);
    }
    bn res;
    memset(&res, 0, sizeof res);
    memcpy(res.w, t, (size_t)k * 4);
    if (t[k] || bn_cmp(&res, n, k) >= 0)
        bn_sub(&res, &res, n, k);
    *r = res;
}

int opk_rsa_public(const uint8_t *mod, size_t mod_len, const uint8_t *exp, size_t exp_len, const uint8_t *in,
                   uint8_t *out)
{
    if (mod_len == 0 || mod_len > OPK_MAX_RSA_BYTES || !(mod[mod_len - 1] & 1) || exp_len == 0 || exp_len > 4)
        return OPK_ERR_PARAM;
    int k = (int)((mod_len + 3) / 4);
    bn n, a, rr, x, one;
    bn_from_bytes(&n, mod, mod_len, k);
    bn_from_bytes(&a, in, mod_len, k);
    /* reduce input (same byte length as n, so it is < 256 * n) */
    for (int guard = 0; bn_cmp(&a, &n, k) >= 0 && guard < 300; guard++)
        bn_sub(&a, &a, &n, k);
    /* n0inv = -n^-1 mod 2^32 (Newton iteration) */
    uint32_t inv = 1;
    for (int i = 0; i < 5; i++)
        inv *= 2 - n.w[0] * inv;
    uint32_t n0inv = (uint32_t)(0 - inv);
    /* rr = R^2 mod n by doubling 1 (2*32*k) times */
    memset(&rr, 0, sizeof rr);
    rr.w[0] = 1;
    for (int i = 0; i < 64 * k; i++) {
        uint32_t carry = 0;
        for (int j = 0; j < k; j++) {
            uint32_t nc = rr.w[j] >> 31;
            rr.w[j] = (rr.w[j] << 1) | carry;
            carry = nc;
        }
        if (carry || bn_cmp(&rr, &n, k) >= 0)
            bn_sub(&rr, &rr, &n, k);
    }
    memset(&one, 0, sizeof one);
    one.w[0] = 1;
    bn am, xm;
    mont_mul(&am, &a, &rr, &n, n0inv, k);
    mont_mul(&xm, &one, &rr, &n, n0inv, k);
    uint32_t e = 0;
    for (size_t i = 0; i < exp_len; i++)
        e = (e << 8) | exp[i];
    int top = 31;
    while (top >= 0 && !((e >> top) & 1))
        top--;
    for (int i = top; i >= 0; i--) {
        mont_mul(&xm, &xm, &xm, &n, n0inv, k);
        if ((e >> i) & 1)
            mont_mul(&xm, &xm, &am, &n, n0inv, k);
    }
    mont_mul(&x, &xm, &one, &n, n0inv, k);
    bn_to_bytes(&x, out, mod_len);
    return OPK_OK;
}
