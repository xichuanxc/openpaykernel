/* Internal interfaces shared between OpenPayKernel source files.
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef OPK_INTERNAL_H
#define OPK_INTERNAL_H

#include "openpaykernel/openpaykernel.h"

#include <string.h>

/* ------------------------------------------------------------------ TLV */
typedef struct {
    uint32_t tag;
    const uint8_t *val;
    size_t len;
    const uint8_t *raw;   /* start of the encoded object */
    size_t raw_len;
} opk_tlv;

int opk_tlv_constructed(uint32_t tag);
/* Read the next object at *pos (padding skipped). Return 1 = got one, 0 = end, <0 = error. */
int opk_tlv_next(const uint8_t *buf, size_t len, size_t *pos, opk_tlv *out);
/* Depth-first search through buf for tag. Return 1 if found. */
int opk_tlv_find(const uint8_t *buf, size_t len, uint32_t tag, opk_tlv *out);
/* Validate the whole buffer. Return 0 if it is well formed. */
int opk_tlv_check(const uint8_t *buf, size_t len);
/* Store every primitive object in buf into db. Return 0 or an error. */
int opk_tlv_store_all(opk_db *db, const uint8_t *buf, size_t len);
/* Like store_all, but skips terminal-sourced tags: card data must never overwrite terminal data. */
int opk_tlv_store_card(opk_db *db, const uint8_t *buf, size_t len);
size_t opk_tlv_encode(uint32_t tag, const uint8_t *val, size_t len, uint8_t *out);
int opk_tlv_parse_tag(const uint8_t *buf, size_t len, size_t *pos, uint32_t *tag);
int opk_tlv_parse_len(const uint8_t *buf, size_t len, size_t *pos, size_t *out);

/* ------------------------------------------------------------------ data dictionary */
char opk_tag_format(uint32_t tag);     /* 'n', 'c' (cn), 'a' (an/ans), 'b' */
int opk_tag_is_terminal(uint32_t tag);

/* ------------------------------------------------------------------ DOL */
int opk_dol_build(const uint8_t *dol, size_t dol_len, const opk_db *db, uint8_t *out, size_t cap, size_t *out_len);
int opk_dol_contains(const uint8_t *dol, size_t dol_len, uint32_t tag);

/* ------------------------------------------------------------------ crypto */
void opk_sha1(const uint8_t *data, size_t len, uint8_t out[20]);
typedef struct {
    uint32_t h[5];
    uint64_t total;
    uint8_t buf[64];
    size_t buf_len;
} opk_sha1_ctx;
void opk_sha1_init(opk_sha1_ctx *c);
void opk_sha1_update(opk_sha1_ctx *c, const uint8_t *d, size_t n);
void opk_sha1_final(opk_sha1_ctx *c, uint8_t out[20]);
/* out = in^e mod n; all big-endian; len(in) == len(out) == mod_len */
int opk_rsa_public(const uint8_t *mod, size_t mod_len, const uint8_t *exp, size_t exp_len,
                   const uint8_t *in, uint8_t *out);

/* ------------------------------------------------------------------ ODA */
typedef struct {
    uint8_t modulus[OPK_MAX_RSA_BYTES];
    size_t modulus_len;
    uint8_t exponent[3];
    size_t exponent_len;
} opk_pubkey;

int opk_oda_issuer_pk(const opk_capk *capk, const opk_db *db, const char *today, opk_pubkey *out);
int opk_oda_icc_pk(const opk_pubkey *issuer, const uint8_t *cert, size_t cert_len, const uint8_t *rem,
                   size_t rem_len, const uint8_t *exp, size_t exp_len, const uint8_t *static_data,
                   size_t static_len, const uint8_t *pan, size_t pan_len, const char *today, opk_pubkey *out);
int opk_oda_verify_sda(const opk_pubkey *issuer, const uint8_t *ssad, size_t ssad_len,
                       const uint8_t *static_data, size_t static_len, uint8_t dac[2]);
/* On success *dd / *dd_len point into the caller's scratch buffer (ICC dynamic data). */
int opk_oda_verify_dynamic(const opk_pubkey *icc, const uint8_t *sdad, size_t sdad_len, const uint8_t *tdd,
                           size_t tdd_len, uint8_t *scratch, const uint8_t **dd, size_t *dd_len);
int opk_oda_verify_cda(const opk_pubkey *icc, const uint8_t *sdad, size_t sdad_len, const uint8_t *un,
                       size_t un_len, uint8_t cid, const uint8_t *tx_hash_input, size_t tx_len, uint8_t ac[8]);

/* ------------------------------------------------------------------ session (shared EMV processing) */
typedef struct {
    const opk_env *env;
    const opk_aid_config *aid;
    const opk_transaction *txn;
    const opk_reader *reader;
    opk_db *db;
    uint8_t tvr[5];
    uint8_t tsi[2];
    uint8_t static_data[OPK_STATIC_DATA_MAX];
    size_t static_len;
    int static_invalid;
    uint8_t pdol_data[256];
    size_t pdol_len;
    uint8_t cdol1_data[256];
    size_t cdol1_len;
    /* last response */
    uint8_t rsp[512];
    size_t rsp_len;
    uint16_t sw;
} opk_session;

#define TVR(s, byte, bit) ((s)->tvr[(byte) - 1] |= (uint8_t)(1u << ((bit) - 1)))
#define TSI(s, byte, bit) ((s)->tsi[(byte) - 1] |= (uint8_t)(1u << ((bit) - 1)))
#define BIT(p, byte, bit) (((p)[(byte) - 1] >> ((bit) - 1)) & 1u)

#define OPK_MAX_COMMAND_DATA 252  /* DOL data must fit a short command APDU */

#define AC_AAC  0x00
#define AC_TC   0x40
#define AC_ARQC 0x80
#define AC_CDA  0x10

void opk_session_init(opk_session *s, const opk_env *env, const opk_aid_config *aid, const opk_transaction *txn,
                      const opk_reader *reader, opk_db *db);
void opk_session_sync(opk_session *s);
int opk_bit(const opk_db *db, uint32_t tag, int byte, int bit);
int opk_exchange(opk_session *s, const uint8_t *capdu, size_t clen);
int opk_xchg(const opk_reader *r, const uint8_t *capdu, size_t clen, uint8_t *rsp, size_t *rsp_len, uint16_t *sw);
size_t opk_cmd(uint8_t *out, uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2, const uint8_t *data, size_t dlen,
               int le);
size_t opk_cmd_select(uint8_t *out, const uint8_t *name, size_t len, int first);
int opk_build_dol_tag(opk_session *s, uint32_t dol_tag, const uint8_t *fallback, size_t fallback_len,
                      uint8_t *out, size_t cap, size_t *out_len);
int opk_gpo(opk_session *s);   /* sends GPO with pdol_data; returns OPK_OK or OPK_ERR_CARD; s->sw set */
int opk_parse_gpo(opk_session *s);
int opk_read_application_data(opk_session *s);
int opk_check_mandatory(opk_session *s, const uint32_t *tags, int n);
int opk_retrieve_issuer_pk(opk_session *s, opk_pubkey *out);
int opk_retrieve_icc_pk(opk_session *s, opk_pubkey *out);
int opk_static_data(opk_session *s, uint8_t *out, size_t cap, size_t *len);
int opk_processing_restrictions(opk_session *s);  /* OPK_ERR_CARD on malformed dates */
const opk_capk *opk_find_capk(const opk_env *env, const uint8_t *rid, uint8_t index, const char *today);
int64_t opk_bcd_to_int(const uint8_t *b, size_t len);
long opk_yymmdd(const uint8_t *bcd3);
int opk_valid_date(const uint8_t *d, size_t len);
long opk_yymmdd_str(const char *s);
int opk_pan_on_exception_file(const opk_env *env, const uint8_t *pan, size_t len);

/* CVM */
#define OPK_RESULT_UNKNOWN 0
#define OPK_RESULT_FAILED  1
#define OPK_RESULT_SUCCESS 2
typedef int (*opk_pin_fn)(opk_session *s, uint8_t method, void *ctx);
typedef struct {
    uint8_t results[3];
    int signature, online_pin, offline_pin;
} opk_cvm_result;
void opk_cvm_list_processing(opk_session *s, const uint8_t caps[3], opk_pin_fn perform, void *ctx,
                             opk_cvm_result *out);

void opk_terminal_risk_management(opk_session *s);
int opk_terminal_action_analysis(opk_session *s, const uint8_t *tac_denial, const uint8_t *tac_online,
                                 const uint8_t *tac_default, int online_capable);
int opk_default_action(opk_session *s, const uint8_t *tac_default);
/* Parse a GENERATE AC response held in s->rsp. children/children_len receive the 77 template body. */
int opk_parse_generate_ac(opk_session *s, const uint8_t **children, size_t *children_len);
int opk_online_capable(const opk_terminal_config *t);
int opk_terminal_attended(const opk_terminal_config *t);

/* outcome helpers */
void opk_outcome_set(opk_outcome *o, opk_status st, opk_cvm cvm, opk_message msg);
void opk_outcome_end(opk_outcome *o, opk_l2_error l2, uint16_t sw, opk_message msg);

/* contactless kernels */
typedef struct {
    const opk_env *env;
    const opk_transaction *txn;
    const opk_reader *reader;
    const opk_aid_config *aid;
    const uint8_t *adf_name;
    size_t adf_len;
    const uint8_t *fci;
    size_t fci_len;
    uint8_t ttq[4];
    int has_ttq;
    opk_db *db;
} opk_kernel_ctx;

int opk_kernel_visa(const opk_kernel_ctx *k, opk_outcome *out);
int opk_kernel_mastercard(const opk_kernel_ctx *k, opk_outcome *out);
int opk_kernel_discover(const opk_kernel_ctx *k, opk_outcome *out);
int opk_kernel_amex(const opk_kernel_ctx *k, opk_outcome *out);
int opk_kernel_jcb(const opk_kernel_ctx *k, opk_outcome *out);

/* shared steps of the GENERATE AC kernels (opk_kernel_common.c) */
#define OPK_K_CDA_FAILED  (-100) /* CDA verification failed; TVR "CDA failed" is set */
#define OPK_K_STATUS_WORD (-101) /* GENERATE AC returned an error SW (in s->sw) */
int opk_k_store_fci(opk_session *s, const opk_kernel_ctx *k); /* 1 ok, 0 not an FCI, <0 malformed */
int opk_k_select_cda(opk_session *s, const uint8_t aip[2], int terminal_supports_cda);
int opk_k_generate_ac(opk_session *s, int ac, int cda); /* cid >= 0, or OPK_K_* / OPK_ERR_* */
opk_status opk_k_status_for(int cid);
int opk_k_no_pin(opk_session *s, uint8_t method, void *ctx);
void opk_k_final(opk_session *s, opk_outcome *o, opk_status st, opk_cvm cvm, opk_l2_error l2);
void opk_k_select_next(opk_outcome *o, opk_l2_error l2, uint16_t sw);
void opk_k_try_another_interface(opk_outcome *o);

#endif
