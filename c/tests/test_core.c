/* Unit tests for the OpenPayKernel primitives: TLV, DOL, SHA-1, RSA. */
#include "../src/opk_internal.h"

#include <stdio.h>

static int fails;
#define CHECK(c)                                                                 \
    do {                                                                         \
        if (!(c)) {                                                              \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #c); \
            fails++;                                                             \
        }                                                                        \
    } while (0)

static void test_tlv(void)
{
    static const uint8_t fci[] = {0x6F, 0x1A, 0x84, 0x0E, '1', 'P', 'A', 'Y', '.', 'S', 'Y', 'S', '.', 'D', 'D',
                                  'F', '0', '1', 0xA5, 0x08, 0x88, 0x01, 0x02, 0x5F, 0x2D, 0x02, 'e', 'n'};
    opk_tlv t;
    CHECK(opk_tlv_check(fci, sizeof fci) == OPK_OK);
    CHECK(opk_tlv_find(fci, sizeof fci, 0x88, &t) == 1 && t.len == 1 && t.val[0] == 2);
    CHECK(opk_tlv_find(fci, sizeof fci, 0x5F2D, &t) == 1 && t.len == 2);
    static const uint8_t bad[] = {0x9F, 0x02, 0x05, 0x00};
    CHECK(opk_tlv_check(bad, sizeof bad) != OPK_OK);
    uint8_t enc[300], big[200] = {0};
    size_t n = opk_tlv_encode(0x9F46, big, 200, enc);
    CHECK(n == 204 && enc[2] == 0x81 && enc[3] == 200);
}

static void test_db_and_dol(void)
{
    static opk_db db;
    opk_db_init(&db);
    opk_db_set(&db, 0x9F02, (const uint8_t *)"\x00\x00\x00\x00\x10\x00", 6);
    opk_db_set(&db, 0x5A, (const uint8_t *)"\x47\x61\x73\x90\x01\x01\x00\x10", 8);
    opk_db_set(&db, 0x50, (const uint8_t *)"VISA", 4);
    opk_db_set(&db, 0x9F37, (const uint8_t *)"\x11\x22\x33\x44", 4);
    static const uint8_t dol[] = {0x9F, 0x02, 0x04, 0x5A, 0x0A, 0x50, 0x06, 0x9F, 0x37, 0x02, 0x9F, 0x4C, 0x08,
                                  0x70, 0x04};
    static const uint8_t want[] = {0x00, 0x00, 0x10, 0x00, 0x47, 0x61, 0x73, 0x90, 0x01, 0x01, 0x00, 0x10,
                                   0xFF, 0xFF, 'V', 'I', 'S', 'A', 0, 0, 0x11, 0x22, 0, 0, 0, 0, 0, 0,
                                   0, 0, 0, 0, 0, 0};
    uint8_t out[64];
    size_t n;
    CHECK(opk_dol_build(dol, sizeof dol, &db, out, sizeof out, &n) == OPK_OK);
    CHECK(n == sizeof want && !memcmp(out, want, n));
    /* overwrite with longer value */
    opk_db_set(&db, 0x50, (const uint8_t *)"MASTERCARD", 10);
    size_t l;
    const uint8_t *v = opk_db_get(&db, 0x50, &l);
    CHECK(l == 10 && !memcmp(v, "MASTERCARD", 10));
    opk_db_del(&db, 0x50);
    CHECK(!opk_db_has(&db, 0x50));
}

static void test_sha1(void)
{
    uint8_t h[20];
    static const uint8_t abc[20] = {0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A, 0xBA, 0x3E,
                                    0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C, 0x9C, 0xD0, 0xD8, 0x9D};
    opk_sha1((const uint8_t *)"abc", 3, h);
    CHECK(!memcmp(h, abc, 20));
    static const uint8_t m[20] = {0x84, 0x98, 0x3E, 0x44, 0x1C, 0x3B, 0xD2, 0x6E, 0xBA, 0xAE,
                                  0x4A, 0xA1, 0xF9, 0x51, 0x29, 0xE5, 0xE5, 0x46, 0x70, 0xF1};
    opk_sha1((const uint8_t *)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, h);
    CHECK(!memcmp(h, m, 20));
}

static void test_rsa(void)
{
    /* Montgomery exponentiation against values small enough to check by hand (odd 64-bit modulus) */
    static const uint8_t n[8] = {0xD4, 0x31, 0xBD, 0x6D, 0x3F, 0x7B, 0x2C, 0x0F};
    uint8_t x[8] = {0, 0, 0, 0, 0, 0, 0x01, 0x23}, y[8];
    /* 0x123^3 = 0x0178027B (no reduction needed) */
    CHECK(opk_rsa_public(n, 8, (const uint8_t *)"\x03", 1, x, y) == OPK_OK);
    static const uint8_t want[8] = {0, 0, 0, 0, 0x01, 0x78, 0x02, 0x7B};
    CHECK(!memcmp(y, want, 8));
    /* e = 1 returns the reduced input */
    uint8_t big[8] = {0xD4, 0x31, 0xBD, 0x6D, 0x3F, 0x7B, 0x2C, 0x10};
    CHECK(opk_rsa_public(n, 8, (const uint8_t *)"\x01", 1, big, y) == OPK_OK);
    static const uint8_t one[8] = {0, 0, 0, 0, 0, 0, 0, 1};
    CHECK(!memcmp(y, one, 8));
}

int main(void)
{
    test_tlv();
    test_db_and_dol();
    test_sha1();
    test_rsa();
    printf("core tests: %s\n", fails ? "FAIL" : "ok");
    return fails ? 1 : 0;
}
