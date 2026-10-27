/*
 * OpenPayKernel - open-source EMV Level 2 kernel (contact + contactless)
 *
 * Public API. All storage is caller-owned and fixed-size; the library never
 * allocates memory. See docs/ARCHITECTURE.md for the design.
 *
 * STUDY / RESEARCH USE ONLY. Not certified by EMVCo or any payment brand, not
 * security-audited, not guaranteed to be bug-free, and provided "AS IS" without
 * warranty (Apache-2.0). Do not use it to process real payments.
 * See the Disclaimer in README.md.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef OPENPAYKERNEL_H
#define OPENPAYKERNEL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OPK_VERSION "0.1.0"

/* ------------------------------------------------------------------ limits */
#define OPK_DB_MAX_ENTRIES 192
#define OPK_DB_POOL_SIZE   12288
#define OPK_MAX_AIDS       16
#define OPK_MAX_CAPKS      32
#define OPK_MAX_CANDIDATES 16
#define OPK_MAX_RSA_BYTES  256
#define OPK_MAX_EXTRA_TLV  512
#define OPK_STATIC_DATA_MAX 2048
#define OPK_EXCEPTION_FILE_MAX 8

/* ------------------------------------------------------------------ errors */
typedef enum {
    OPK_OK = 0,
    OPK_ERR_PARAM = -1,
    OPK_ERR_TLV = -2,
    OPK_ERR_FULL = -3,
    OPK_ERR_NOT_FOUND = -4,
    OPK_ERR_CARD = -5,       /* card data / protocol violation */
    OPK_ERR_TRANSMIT = -6,   /* level-1 error reported by the reader */
    OPK_ERR_ODA = -7
} opk_err;

/* ------------------------------------------------------------------ TLV database */
typedef struct {
    uint32_t tag;
    uint16_t off;
    uint16_t len;
} opk_db_entry;

typedef struct {
    opk_db_entry e[OPK_DB_MAX_ENTRIES];
    int count;
    uint8_t pool[OPK_DB_POOL_SIZE];
    uint16_t used;
} opk_db;

void opk_db_init(opk_db *db);
int opk_db_set(opk_db *db, uint32_t tag, const uint8_t *val, size_t len);
const uint8_t *opk_db_get(const opk_db *db, uint32_t tag, size_t *len);
int opk_db_has(const opk_db *db, uint32_t tag);
void opk_db_del(opk_db *db, uint32_t tag);

/* ------------------------------------------------------------------ outcome (Book A) */
typedef enum {
    OPK_STATUS_APPROVED = 1,
    OPK_STATUS_DECLINED = 2,
    OPK_STATUS_ONLINE_REQUEST = 3,
    OPK_STATUS_END_APPLICATION = 4,
    OPK_STATUS_SELECT_NEXT = 5,
    OPK_STATUS_TRY_ANOTHER_INTERFACE = 6,
    OPK_STATUS_TRY_AGAIN = 7,
    OPK_STATUS_NA = 15
} opk_status;

typedef enum {
    OPK_CVM_NO_CVM = 0,
    OPK_CVM_SIGNATURE = 1,
    OPK_CVM_ONLINE_PIN = 2,
    OPK_CVM_CONFIRMATION_CODE_VERIFIED = 3,
    OPK_CVM_OFFLINE_PIN = 4,
    OPK_CVM_NA = 15
} opk_cvm;

typedef enum {
    OPK_L2_OK = 0, OPK_L2_CARD_DATA_MISSING = 1, OPK_L2_CAM_FAILED = 2, OPK_L2_STATUS_BYTES = 3,
    OPK_L2_PARSING_ERROR = 4, OPK_L2_MAX_LIMIT_EXCEEDED = 5, OPK_L2_CARD_DATA_ERROR = 6,
    OPK_L2_MAGSTRIPE_NOT_SUPPORTED = 7, OPK_L2_NO_PPSE = 8, OPK_L2_PPSE_FAULT = 9,
    OPK_L2_EMPTY_CANDIDATE_LIST = 10
} opk_l2_error;

typedef enum {
    OPK_MSG_APPROVED = 0x03, OPK_MSG_NOT_AUTHORISED = 0x07, OPK_MSG_PROCESSING_ERROR = 0x0F,
    OPK_MSG_PRESENT_CARD = 0x15, OPK_MSG_APPROVED_SIGN = 0x1A, OPK_MSG_AUTHORISING = 0x1B,
    OPK_MSG_INSERT_SWIPE_OR_TRY_ANOTHER = 0x1C, OPK_MSG_INSERT_CARD = 0x1D, OPK_MSG_SEE_PHONE = 0x20,
    OPK_MSG_PRESENT_CARD_AGAIN = 0x21, OPK_MSG_NA = 0xFF
} opk_message;

typedef struct {
    opk_status status;
    uint8_t start;            /* 0=A 1=B 2=C 3=D 15=N/A */
    opk_cvm cvm;
    opk_message ui_message;
    uint8_t receipt;
    uint8_t alt_interface_contact;
    uint16_t field_off_ms;
    uint8_t l1_error;
    opk_l2_error l2_error;
    uint16_t sw12;
} opk_outcome;

/* ------------------------------------------------------------------ host interfaces */
typedef struct {
    /* Exchange one APDU. Return 0 on success, <0 on a level-1 error. */
    int (*transmit)(void *ctx, const uint8_t *capdu, size_t clen, uint8_t *rapdu, size_t *rlen);
    void *ctx;
} opk_reader;

typedef void (*opk_rng_fn)(void *ctx, uint8_t *out, size_t n);

/* ------------------------------------------------------------------ configuration */
typedef struct {
    uint8_t rid[5];
    uint8_t index;
    uint8_t modulus[OPK_MAX_RSA_BYTES];
    uint16_t modulus_len;
    uint8_t exponent[3];
    uint8_t exponent_len;
    char expiry[7];           /* YYMMDD */
} opk_capk;

typedef struct {
    uint8_t aid[16];
    uint8_t aid_len;
    uint32_t kernel_id;       /* 0 = from RID */
    uint8_t partial_match;
    uint8_t app_version[2];
    uint8_t tac_default[5], tac_denial[5], tac_online[5];
    uint32_t floor_limit;
    int64_t cl_transaction_limit;      /* -1 = not configured */
    int64_t cl_transaction_limit_cdcvm;
    int64_t cvm_required_limit;
    uint32_t threshold;
    uint8_t target_percent, max_target_percent;
    uint8_t default_ddol[32];
    uint8_t default_ddol_len;
    uint8_t ttq[4];
    uint8_t status_check;
    uint8_t zero_amount_allowed;
    uint8_t extra[OPK_MAX_EXTRA_TLV];  /* kernel-specific TLVs, e.g. DF81xx for kernel 2 */
    uint16_t extra_len;
} opk_aid_config;

typedef struct {
    uint8_t country_code[2];
    uint8_t terminal_type;
    uint8_t capabilities[3];
    uint8_t additional_capabilities[5];
    uint8_t terminal_id[8];
    uint8_t ifd_serial[8];
    uint8_t merchant_category_code[2];
    uint8_t merchant_id[15];
    uint8_t merchant_name_location[17];
    uint8_t merchant_name_location_len;
    char exception_file[OPK_EXCEPTION_FILE_MAX][20];  /* hot-listed PANs (ASCII digits) */
    int exception_file_count;
} opk_terminal_config;

typedef struct {
    uint32_t amount;
    uint32_t amount_other;
    uint8_t currency_code[2];
    uint8_t currency_exponent;
    uint8_t type;
    char date[7];             /* YYMMDD */
    char time[7];             /* HHMMSS */
    uint32_t sequence_counter;
    uint8_t force_online;
} opk_transaction;

typedef struct {
    opk_terminal_config terminal;
    opk_aid_config aids[OPK_MAX_AIDS];
    int aid_count;
    opk_capk capks[OPK_MAX_CAPKS];
    int capk_count;
    opk_rng_fn rng;
    void *rng_ctx;
} opk_env;

void opk_terminal_defaults(opk_terminal_config *t);
void opk_aid_defaults(opk_aid_config *a, const uint8_t *aid, size_t aid_len);
void opk_transaction_defaults(opk_transaction *t, uint32_t amount);
int opk_env_add_capk(opk_env *env, const opk_capk *k);

/* ------------------------------------------------------------------ contactless */
#define OPK_KERNEL_MASTERCARD 2u
#define OPK_KERNEL_VISA       3u

/* Run one contactless transaction: pre-processing, PPSE, final selection, kernel.
 * `db` receives the transaction data (data record) on return. */
int opk_contactless_process(const opk_env *env, const opk_transaction *txn, const opk_reader *reader,
                            opk_outcome *out, opk_db *db);

/* ------------------------------------------------------------------ contact */
typedef struct {
    uint8_t aid[16];
    uint8_t aid_len;
    char label[17];
    uint8_t priority;
    uint8_t needs_confirmation;
    int cfg_index;
} opk_app_candidate;

typedef struct {
    uint8_t approved;
    uint8_t arc[2];
    uint8_t issuer_auth_data[16];
    uint8_t issuer_auth_data_len;   /* 0 = absent */
    const uint8_t *scripts;         /* concatenated 71/72 templates, may be NULL */
    size_t scripts_len;
} opk_online_response;

typedef struct {
    /* Return index into cands, or -1 to cancel. */
    int (*choose_application)(void *ctx, const opk_app_candidate *cands, int n);
    /* Write a NUL-terminated PIN into pin (size 13). Return 1 if entered, 0 if bypassed.
     * tries_left is -1 if unknown. */
    int (*enter_pin)(void *ctx, int online, int tries_left, char *pin);
    /* Authorise online using the data in db. Return 1 with *rsp filled in, or 0 if unable to go online. */
    int (*go_online)(void *ctx, const opk_db *db, opk_online_response *rsp);
    void *ctx;
} opk_contact_host;

int opk_contact_process(const opk_env *env, const opk_transaction *txn, const opk_reader *reader,
                        const opk_contact_host *host, opk_outcome *out, opk_db *db);

/* ------------------------------------------------------------------ utilities */
const char *opk_status_name(opk_status s);

#ifdef __cplusplus
}
#endif
#endif
