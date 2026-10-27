/* Shared helpers for the C examples: a study configuration, an RNG, an APDU-tracing reader
 * wrapper and outcome printing. STUDY USE ONLY - see the Disclaimer in README.md.
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef OPK_EXAMPLE_COMMON_H
#define OPK_EXAMPLE_COMMON_H

#include <openpaykernel/openpaykernel.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Terminal unpredictable numbers. Use your platform's secure RNG in a real terminal. */
static void example_rng(void *ctx, uint8_t *out, size_t n)
{
    (void)ctx;
    FILE *f = fopen("/dev/urandom", "rb");
    if (f && fread(out, 1, n, f) == n) {
        fclose(f);
        return;
    }
    if (f)
        fclose(f);
    for (size_t i = 0; i < n; i++)
        out[i] = (uint8_t)rand();
}

/* Append a 3-byte-tag TLV (DF81xx kernel configuration) given as hex. */
static void add_tlv(opk_aid_config *a, uint32_t tag, const char *hex)
{
    uint8_t v[32];
    size_t n = strlen(hex) / 2;
    for (size_t i = 0; i < n; i++) {
        unsigned b;
        sscanf(hex + 2 * i, "%2x", &b);
        v[i] = (uint8_t)b;
    }
    a->extra[a->extra_len++] = (uint8_t)(tag >> 16);
    a->extra[a->extra_len++] = (uint8_t)(tag >> 8);
    a->extra[a->extra_len++] = (uint8_t)tag;
    a->extra[a->extra_len++] = (uint8_t)n;
    memcpy(a->extra + a->extra_len, v, n);
    a->extra_len = (uint16_t)(a->extra_len + n);
}

/* Visa + UnionPay + Discover + Mastercard study configuration (no CA public keys: ODA will fail, as expected). */
static void example_env(opk_env *env)
{
    memset(env, 0, sizeof *env);
    opk_terminal_defaults(&env->terminal);
    env->rng = example_rng;

    opk_aid_config *visa = &env->aids[env->aid_count++];
    opk_aid_defaults(visa, (const uint8_t *)"\xA0\x00\x00\x00\x03\x10\x10", 7);
    visa->kernel_id = OPK_KERNEL_VISA;
    visa->floor_limit = 10000;
    visa->cl_transaction_limit = 50000;
    visa->cvm_required_limit = 3000;
    memcpy(visa->tac_default, "\xDC\x40\x00\xA8\x00", 5);
    memcpy(visa->tac_denial, "\x00\x10\x00\x00\x00", 5);
    memcpy(visa->tac_online, "\xDC\x40\x04\xF8\x00", 5);

    opk_aid_config *upi = &env->aids[env->aid_count++];
    opk_aid_defaults(upi, (const uint8_t *)"\xA0\x00\x00\x03\x33\x01\x01", 7); /* partial: 0101xx */
    upi->kernel_id = OPK_KERNEL_UNIONPAY;
    upi->floor_limit = 10000;
    upi->cl_transaction_limit = 50000;
    upi->cvm_required_limit = 3000;
    memcpy(upi->tac_default, "\xD8\x40\x00\xA8\x00", 5);
    memcpy(upi->tac_denial, "\x00\x10\x00\x00\x00", 5);
    memcpy(upi->tac_online, "\xD8\x40\x04\xF8\x00", 5);

    opk_aid_config *disc = &env->aids[env->aid_count++];
    opk_aid_defaults(disc, (const uint8_t *)"\xA0\x00\x00\x01\x52\x30\x10", 7);
    disc->kernel_id = OPK_KERNEL_DISCOVER;
    disc->floor_limit = 10000;
    disc->cl_transaction_limit = 50000;
    disc->cvm_required_limit = 3000;
    memcpy(disc->tac_default, "\xDC\x40\x00\xA8\x00", 5);
    memcpy(disc->tac_denial, "\x00\x10\x00\x00\x00", 5);
    memcpy(disc->tac_online, "\xDC\x40\x04\xF8\x00", 5);

    opk_aid_config *mc = &env->aids[env->aid_count++];
    opk_aid_defaults(mc, (const uint8_t *)"\xA0\x00\x00\x00\x04\x10\x10", 7);
    mc->kernel_id = OPK_KERNEL_MASTERCARD;
    mc->floor_limit = 10000;
    memcpy(mc->tac_default, "\xFC\x50\xA8\xA0\x00", 5);
    memcpy(mc->tac_online, "\xFC\x50\xA8\xF8\x00", 5);
    add_tlv(mc, 0xDF811B, "20");           /* kernel configuration */
    add_tlv(mc, 0xDF811F, "08");           /* security capability: CDA */
    add_tlv(mc, 0xDF8118, "60");           /* CVM capability, CVM required */
    add_tlv(mc, 0xDF8119, "08");           /* CVM capability, no CVM required */
    add_tlv(mc, 0xDF8123, "000000010000"); /* reader contactless floor limit */
    add_tlv(mc, 0xDF8124, "000000030000"); /* CL transaction limit, no on-device CVM */
    add_tlv(mc, 0xDF8125, "000000050000"); /* CL transaction limit, on-device CVM */
    add_tlv(mc, 0xDF8126, "000000003000"); /* CVM required limit */
}

static void example_transaction(opk_transaction *txn, uint32_t amount)
{
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    opk_transaction_defaults(txn, amount);
    strftime(txn->date, sizeof txn->date, "%y%m%d", tm);
    strftime(txn->time, sizeof txn->time, "%H%M%S", tm);
}

/* Wraps any opk_reader and prints every APDU. */
typedef struct {
    opk_reader inner;
} tracing_reader;

static void print_hex(const char *prefix, const uint8_t *b, size_t n)
{
    printf("%s", prefix);
    for (size_t i = 0; i < n; i++)
        printf("%02X", b[i]);
    printf("\n");
}

static int tracing_transmit(void *ctx, const uint8_t *c, size_t cl, uint8_t *r, size_t *rl)
{
    tracing_reader *t = ctx;
    print_hex("  > ", c, cl);
    int rc = t->inner.transmit(t->inner.ctx, c, cl, r, rl);
    if (rc < 0)
        printf("  < (level-1 error %d)\n", rc);
    else
        print_hex("  < ", r, *rl);
    return rc;
}

static void example_print_outcome(const opk_outcome *out, const opk_db *db)
{
    static const uint32_t tags[] = {0x95, 0x9B, 0x9F34, 0x9F27, 0x9F26, 0x8A};
    printf("\noutcome: %s   CVM: %d   L1 error: %d   L2 error: %d   SW: %04X\n", opk_status_name(out->status),
           out->cvm, out->l1_error, out->l2_error, out->sw12);
    for (size_t i = 0; i < sizeof tags / sizeof tags[0]; i++) {
        size_t l;
        const uint8_t *v = opk_db_get(db, tags[i], &l);
        if (v) {
            char p[16];
            snprintf(p, sizeof p, "  %6X ", tags[i]);
            print_hex(p, v, l);
        }
    }
}

#endif
