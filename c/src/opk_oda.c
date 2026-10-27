/* Offline Data Authentication: certificate recovery and signature checks (EMV Book 2).
 * SPDX-License-Identifier: Apache-2.0 */
#include "opk_internal.h"

static int recover(const uint8_t *mod, size_t mod_len, const uint8_t *exp, size_t exp_len, const uint8_t *data,
                   size_t data_len, uint8_t *out)
{
    if (data_len != mod_len)
        return OPK_ERR_ODA;
    return opk_rsa_public(mod, mod_len, exp, exp_len, data, out) ? OPK_ERR_ODA : OPK_OK;
}

static int check_frame(const uint8_t *rec, size_t n, uint8_t fmt)
{
    return (rec[0] == 0x6A && rec[n - 1] == 0xBC && rec[1] == fmt) ? OPK_OK : OPK_ERR_ODA;
}

/* SHA-1(rec[1 .. n-22] || a || b || c) == rec[n-21 .. n-2] */
static int check_hash(const uint8_t *rec, size_t n, const uint8_t *a, size_t al, const uint8_t *b, size_t bl,
                      const uint8_t *c, size_t cl)
{
    opk_sha1_ctx ctx;
    uint8_t h[20];
    opk_sha1_init(&ctx);
    opk_sha1_update(&ctx, rec + 1, n - 22);
    if (al) opk_sha1_update(&ctx, a, al);
    if (bl) opk_sha1_update(&ctx, b, bl);
    if (cl) opk_sha1_update(&ctx, c, cl);
    opk_sha1_final(&ctx, h);
    return memcmp(h, rec + n - 21, 20) ? OPK_ERR_ODA : OPK_OK;
}

static int expired(const uint8_t mmyy[2], const char *today)
{
    int mm = (mmyy[0] >> 4) * 10 + (mmyy[0] & 0x0F);
    int yy = (mmyy[1] >> 4) * 10 + (mmyy[1] & 0x0F);
    int cert = (yy < 50 ? 2000 + yy : 1900 + yy) * 100 + mm;
    int ty = (today[0] - '0') * 10 + (today[1] - '0');
    int tm = (today[2] - '0') * 10 + (today[3] - '0');
    int t = (ty < 50 ? 2000 + ty : 1900 + ty) * 100 + tm;
    return cert < t;
}

/* number of significant digits in a cn field (stop at first F nibble) */
static size_t cn_digits(const uint8_t *b, size_t len, char *out)
{
    size_t n = 0;
    for (size_t i = 0; i < len * 2; i++) {
        uint8_t nib = (i & 1) ? (b[i / 2] & 0x0F) : (b[i / 2] >> 4);
        if (nib == 0xF)
            break;
        out[n++] = (char)('0' + nib);
    }
    out[n] = 0;
    return n;
}

static void strip_trailing_f(const uint8_t *b, size_t len, char *out)
{
    /* hex representation with trailing F nibbles removed (matches Python .hex().rstrip("F")) */
    static const char hx[] = "0123456789ABCDEF";
    size_t n = 0;
    for (size_t i = 0; i < len; i++) {
        out[n++] = hx[b[i] >> 4];
        out[n++] = hx[b[i] & 0x0F];
    }
    while (n && out[n - 1] == 'F')
        n--;
    out[n] = 0;
}

int opk_oda_issuer_pk(const opk_capk *capk, const opk_db *db, const char *today, opk_pubkey *out)
{
    size_t cert_len, rem_len = 0, exp_len, pan_len;
    const uint8_t *cert = opk_db_get(db, 0x90, &cert_len);
    const uint8_t *rem = opk_db_get(db, 0x92, &rem_len);
    const uint8_t *exp = opk_db_get(db, 0x9F32, &exp_len);
    const uint8_t *pan = opk_db_get(db, 0x5A, &pan_len);
    uint8_t rec[OPK_MAX_RSA_BYTES];
    if (!cert || !exp || !pan || exp_len > 3)
        return OPK_ERR_ODA;
    if (recover(capk->modulus, capk->modulus_len, capk->exponent, capk->exponent_len, cert, cert_len, rec))
        return OPK_ERR_ODA;
    size_t n = cert_len;
    if (check_frame(rec, n, 0x02) || check_hash(rec, n, rem, rem ? rem_len : 0, exp, exp_len, NULL, 0))
        return OPK_ERR_ODA;
    char id[9], p[21];
    size_t idn = cn_digits(rec + 2, 4, id);
    strip_trailing_f(pan, pan_len, p);
    if (idn < 3 || strncmp(p, id, idn) != 0)
        return OPK_ERR_ODA;
    if (expired(rec + 6, today) || rec[11] != 0x01 || rec[12] != 0x01)
        return OPK_ERR_ODA;
    size_t ni = rec[13], in_cert = n - 36;
    size_t take = ni < in_cert ? ni : in_cert;
    memcpy(out->modulus, rec + 15, take);
    if (ni > in_cert) {
        if (!rem || rem_len != ni - in_cert || ni > OPK_MAX_RSA_BYTES)
            return OPK_ERR_ODA;
        memcpy(out->modulus + take, rem, rem_len);
    }
    out->modulus_len = ni;
    memcpy(out->exponent, exp, exp_len);
    out->exponent_len = exp_len;
    return OPK_OK;
}

int opk_oda_icc_pk(const opk_pubkey *issuer, const uint8_t *cert, size_t cert_len, const uint8_t *rem,
                   size_t rem_len, const uint8_t *exp, size_t exp_len, const uint8_t *static_data, size_t static_len,
                   const uint8_t *pan, size_t pan_len, const char *today, opk_pubkey *out)
{
    uint8_t rec[OPK_MAX_RSA_BYTES];
    if (exp_len > 3 || recover(issuer->modulus, issuer->modulus_len, issuer->exponent, issuer->exponent_len, cert,
                               cert_len, rec))
        return OPK_ERR_ODA;
    size_t n = cert_len;
    if (check_frame(rec, n, 0x04))
        return OPK_ERR_ODA;
    /* hash input: rec[1..] || remainder || exponent || static data */
    opk_sha1_ctx ctx;
    uint8_t h[20];
    opk_sha1_init(&ctx);
    opk_sha1_update(&ctx, rec + 1, n - 22);
    if (rem && rem_len) opk_sha1_update(&ctx, rem, rem_len);
    opk_sha1_update(&ctx, exp, exp_len);
    if (static_len) opk_sha1_update(&ctx, static_data, static_len);
    opk_sha1_final(&ctx, h);
    if (memcmp(h, rec + n - 21, 20))
        return OPK_ERR_ODA;
    char a[21], b[21];
    strip_trailing_f(rec + 2, 10, a);
    strip_trailing_f(pan, pan_len, b);
    if (strcmp(a, b) || expired(rec + 12, today) || rec[17] != 0x01 || rec[18] != 0x01)
        return OPK_ERR_ODA;
    size_t nic = rec[19], in_cert = n - 42;
    size_t take = nic < in_cert ? nic : in_cert;
    memcpy(out->modulus, rec + 21, take);
    if (nic > in_cert) {
        if (!rem || rem_len != nic - in_cert || nic > OPK_MAX_RSA_BYTES)
            return OPK_ERR_ODA;
        memcpy(out->modulus + take, rem, rem_len);
    }
    out->modulus_len = nic;
    memcpy(out->exponent, exp, exp_len);
    out->exponent_len = exp_len;
    return OPK_OK;
}

int opk_oda_verify_sda(const opk_pubkey *issuer, const uint8_t *ssad, size_t ssad_len, const uint8_t *static_data,
                       size_t static_len, uint8_t dac[2])
{
    uint8_t rec[OPK_MAX_RSA_BYTES];
    if (recover(issuer->modulus, issuer->modulus_len, issuer->exponent, issuer->exponent_len, ssad, ssad_len, rec))
        return OPK_ERR_ODA;
    if (check_frame(rec, ssad_len, 0x03) || check_hash(rec, ssad_len, static_data, static_len, NULL, 0, NULL, 0))
        return OPK_ERR_ODA;
    dac[0] = rec[3];
    dac[1] = rec[4];
    return OPK_OK;
}

int opk_oda_verify_dynamic(const opk_pubkey *icc, const uint8_t *sdad, size_t sdad_len, const uint8_t *tdd,
                           size_t tdd_len, uint8_t *scratch, const uint8_t **dd, size_t *dd_len)
{
    if (recover(icc->modulus, icc->modulus_len, icc->exponent, icc->exponent_len, sdad, sdad_len, scratch))
        return OPK_ERR_ODA;
    size_t n = sdad_len;
    if (check_frame(scratch, n, 0x05) || scratch[2] != 0x01)
        return OPK_ERR_ODA;
    size_t ldd = scratch[3];
    if (4 + ldd > n - 21)
        return OPK_ERR_ODA;
    if (check_hash(scratch, n, tdd, tdd_len, NULL, 0, NULL, 0))
        return OPK_ERR_ODA;
    *dd = scratch + 4;
    *dd_len = ldd;
    return OPK_OK;
}

int opk_oda_verify_cda(const opk_pubkey *icc, const uint8_t *sdad, size_t sdad_len, const uint8_t *un, size_t un_len,
                       uint8_t cid, const uint8_t *tx, size_t tx_len, uint8_t ac[8])
{
    uint8_t scratch[OPK_MAX_RSA_BYTES], h[20];
    const uint8_t *dd;
    size_t ddl;
    if (opk_oda_verify_dynamic(icc, sdad, sdad_len, un, un_len, scratch, &dd, &ddl))
        return OPK_ERR_ODA;
    size_t nl = dd[0];
    if (ddl < 1 + nl + 1 + 8 + 20)
        return OPK_ERR_ODA;
    if (dd[1 + nl] != cid)
        return OPK_ERR_ODA;
    opk_sha1(tx, tx_len, h);
    if (memcmp(h, dd + 10 + nl, 20))
        return OPK_ERR_ODA;
    memcpy(ac, dd + 2 + nl, 8);
    return OPK_OK;
}
