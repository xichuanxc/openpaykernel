/* EMV processing shared by the contact and contactless kernels (EMV Book 3 section 10, Book 4 section 6).
 * SPDX-License-Identifier: Apache-2.0 */
#include "opk_internal.h"

/* ------------------------------------------------------------------ defaults */
void opk_terminal_defaults(opk_terminal_config *t)
{
    memset(t, 0, sizeof *t);
    memcpy(t->country_code, "\x08\x40", 2);
    t->terminal_type = 0x22;
    memcpy(t->capabilities, "\xE0\xF8\xC8", 3);
    memcpy(t->additional_capabilities, "\x60\x00\xF0\xA0\x01", 5);
    memcpy(t->terminal_id, "TERM0001", 8);
    memcpy(t->ifd_serial, "00000001", 8);
    memcpy(t->merchant_category_code, "\x54\x11", 2);
    memcpy(t->merchant_id, "MERCHANT0000001", 15);
    memcpy(t->merchant_name_location, "OPEN L2 TEST SHOP", 17);
    t->merchant_name_location_len = 17;
}

void opk_aid_defaults(opk_aid_config *a, const uint8_t *aid, size_t aid_len)
{
    memset(a, 0, sizeof *a);
    memcpy(a->aid, aid, aid_len);
    a->aid_len = (uint8_t)aid_len;
    a->partial_match = 1;
    a->app_version[1] = 0x02;
    a->cl_transaction_limit = -1;
    a->cl_transaction_limit_cdcvm = -1;
    a->cvm_required_limit = -1;
    memcpy(a->default_ddol, "\x9F\x37\x04", 3);
    a->default_ddol_len = 3;
    memcpy(a->ttq, "\x36\x00\x40\x00", 4);
    a->zero_amount_allowed = 1;
}

void opk_transaction_defaults(opk_transaction *t, uint32_t amount)
{
    memset(t, 0, sizeof *t);
    t->amount = amount;
    memcpy(t->currency_code, "\x08\x40", 2);
    t->currency_exponent = 2;
    strcpy(t->date, "261027");
    strcpy(t->time, "120000");
    t->sequence_counter = 1;
}

int opk_env_add_capk(opk_env *env, const opk_capk *k)
{
    if (env->capk_count >= OPK_MAX_CAPKS)
        return OPK_ERR_FULL;
    env->capks[env->capk_count++] = *k;
    return OPK_OK;
}

const char *opk_status_name(opk_status s)
{
    switch (s) {
    case OPK_STATUS_APPROVED: return "APPROVED";
    case OPK_STATUS_DECLINED: return "DECLINED";
    case OPK_STATUS_ONLINE_REQUEST: return "ONLINE_REQUEST";
    case OPK_STATUS_END_APPLICATION: return "END_APPLICATION";
    case OPK_STATUS_SELECT_NEXT: return "SELECT_NEXT";
    case OPK_STATUS_TRY_ANOTHER_INTERFACE: return "TRY_ANOTHER_INTERFACE";
    case OPK_STATUS_TRY_AGAIN: return "TRY_AGAIN";
    default: return "N/A";
    }
}

void opk_outcome_set(opk_outcome *o, opk_status st, opk_cvm cvm, opk_message msg)
{
    memset(o, 0, sizeof *o);
    o->status = st;
    o->start = 15;
    o->cvm = cvm;
    o->ui_message = msg;
    o->receipt = cvm == OPK_CVM_SIGNATURE;
}

void opk_outcome_end(opk_outcome *o, opk_l2_error l2, uint16_t sw, opk_message msg)
{
    opk_outcome_set(o, OPK_STATUS_END_APPLICATION, OPK_CVM_NA, msg);
    o->l2_error = l2;
    o->sw12 = sw;
}

/* ------------------------------------------------------------------ helpers */
static void put_bcd(uint8_t *out, size_t len, uint64_t v)
{
    for (size_t i = 0; i < len; i++) {
        uint8_t lo = (uint8_t)(v % 10); v /= 10;
        uint8_t hi = (uint8_t)(v % 10); v /= 10;
        out[len - 1 - i] = (uint8_t)(hi << 4 | lo);
    }
}

static void hex_to_bytes(const char *s, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++)
        out[i] = (uint8_t)(((s[2 * i] - '0') << 4) | (s[2 * i + 1] - '0'));
}

int64_t opk_bcd_to_int(const uint8_t *b, size_t len)
{
    int64_t v = 0;
    for (size_t i = 0; i < len; i++) {
        if ((b[i] >> 4) > 9 || (b[i] & 0x0F) > 9)
            return 0;
        v = v * 100 + (b[i] >> 4) * 10 + (b[i] & 0x0F);
    }
    return v;
}

int opk_valid_date(const uint8_t *d, size_t len)
{
    if (len != 3)
        return 0;
    for (int i = 0; i < 3; i++)
        if ((d[i] >> 4) > 9 || (d[i] & 0x0F) > 9)
            return 0;
    return 1;
}

long opk_yymmdd(const uint8_t *d)
{
    int yy = (d[0] >> 4) * 10 + (d[0] & 0x0F);
    long mmdd = ((d[1] >> 4) * 10 + (d[1] & 0x0F)) * 100 + (d[2] >> 4) * 10 + (d[2] & 0x0F);
    return (long)(yy < 50 ? 2000 + yy : 1900 + yy) * 10000 + mmdd;
}

long opk_yymmdd_str(const char *s)
{
    uint8_t b[3];
    hex_to_bytes(s, b, 3);
    return opk_yymmdd(b);
}

int opk_online_capable(const opk_terminal_config *t)
{
    int x = t->terminal_type & 0x0F;
    return x == 1 || x == 2 || x == 4 || x == 5;
}

int opk_terminal_attended(const opk_terminal_config *t) { return (t->terminal_type & 0x0F) <= 3; }

int opk_bit(const opk_db *db, uint32_t tag, int byte, int bit)
{
    size_t l;
    const uint8_t *v = opk_db_get(db, tag, &l);
    return v && l >= (size_t)byte && BIT(v, byte, bit);
}

const opk_capk *opk_find_capk(const opk_env *env, const uint8_t *rid, uint8_t index, const char *today)
{
    for (int i = 0; i < env->capk_count; i++) {
        const opk_capk *k = &env->capks[i];
        if (k->index == index && !memcmp(k->rid, rid, 5)) {
            if (today && opk_yymmdd_str(k->expiry) < opk_yymmdd_str(today))
                return NULL;
            return k;
        }
    }
    return NULL;
}

int opk_pan_on_exception_file(const opk_env *env, const uint8_t *pan, size_t len)
{
    static const char hx[] = "0123456789ABCDEF";
    char p[24];
    size_t n = 0;
    for (size_t i = 0; i < len && n + 2 < sizeof p; i++) {
        p[n++] = hx[pan[i] >> 4];
        p[n++] = hx[pan[i] & 0x0F];
    }
    while (n && p[n - 1] == 'F')
        n--;
    p[n] = 0;
    for (int i = 0; i < env->terminal.exception_file_count; i++)
        if (!strcmp(env->terminal.exception_file[i], p))
            return 1;
    return 0;
}

/* ------------------------------------------------------------------ session */
void opk_session_sync(opk_session *s)
{
    opk_db_set(s->db, 0x95, s->tvr, 5);
    opk_db_set(s->db, 0x9B, s->tsi, 2);
}

void opk_session_init(opk_session *s, const opk_env *env, const opk_aid_config *aid, const opk_transaction *txn,
                      const opk_reader *reader, opk_db *db)
{
    const opk_terminal_config *t = &env->terminal;
    uint8_t b[8];
    memset(s, 0, sizeof *s);
    s->env = env;
    s->aid = aid;
    s->txn = txn;
    s->reader = reader;
    s->db = db;
    opk_db_init(db);
    opk_db_set(db, 0x9F1A, t->country_code, 2);
    opk_db_set(db, 0x9F35, &t->terminal_type, 1);
    opk_db_set(db, 0x9F33, t->capabilities, 3);
    opk_db_set(db, 0x9F40, t->additional_capabilities, 5);
    opk_db_set(db, 0x9F1C, t->terminal_id, 8);
    opk_db_set(db, 0x9F1E, t->ifd_serial, 8);
    opk_db_set(db, 0x9F15, t->merchant_category_code, 2);
    opk_db_set(db, 0x9F16, t->merchant_id, 15);
    opk_db_set(db, 0x9F4E, t->merchant_name_location, t->merchant_name_location_len);
    put_bcd(b, 6, txn->amount);
    opk_db_set(db, 0x9F02, b, 6);
    put_bcd(b, 6, txn->amount_other);
    opk_db_set(db, 0x9F03, b, 6);
    b[0] = (uint8_t)(txn->amount >> 24); b[1] = (uint8_t)(txn->amount >> 16);
    b[2] = (uint8_t)(txn->amount >> 8);  b[3] = (uint8_t)txn->amount;
    opk_db_set(db, 0x81, b, 4);
    b[0] = (uint8_t)(txn->amount_other >> 24); b[1] = (uint8_t)(txn->amount_other >> 16);
    b[2] = (uint8_t)(txn->amount_other >> 8);  b[3] = (uint8_t)txn->amount_other;
    opk_db_set(db, 0x9F04, b, 4);
    opk_db_set(db, 0x5F2A, txn->currency_code, 2);
    opk_db_set(db, 0x5F36, &txn->currency_exponent, 1);
    opk_db_set(db, 0x9C, &txn->type, 1);
    hex_to_bytes(txn->date, b, 3);
    opk_db_set(db, 0x9A, b, 3);
    hex_to_bytes(txn->time, b, 3);
    opk_db_set(db, 0x9F21, b, 3);
    put_bcd(b, 4, txn->sequence_counter);
    opk_db_set(db, 0x9F41, b, 4);
    if (aid->extra_len)
        opk_tlv_store_all(db, aid->extra, aid->extra_len);
    opk_db_set(db, 0x9F09, aid->app_version, 2);
    b[0] = (uint8_t)(aid->floor_limit >> 24); b[1] = (uint8_t)(aid->floor_limit >> 16);
    b[2] = (uint8_t)(aid->floor_limit >> 8);  b[3] = (uint8_t)aid->floor_limit;
    opk_db_set(db, 0x9F1B, b, 4);
    env->rng(env->rng_ctx, b, 4);
    opk_db_set(db, 0x9F37, b, 4);
    opk_session_sync(s);
}

/* ------------------------------------------------------------------ APDU */
size_t opk_cmd(uint8_t *out, uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2, const uint8_t *data, size_t dlen,
               int le)
{
    size_t n = 0;
    out[n++] = cla; out[n++] = ins; out[n++] = p1; out[n++] = p2;
    if (dlen) {
        out[n++] = (uint8_t)dlen;
        memcpy(out + n, data, dlen);
        n += dlen;
    }
    if (le >= 0)
        out[n++] = (uint8_t)le;
    return n;
}

size_t opk_cmd_select(uint8_t *out, const uint8_t *name, size_t len, int first)
{
    return opk_cmd(out, 0x00, 0xA4, 0x04, first ? 0x00 : 0x02, name, len, 0);
}

int opk_xchg(const opk_reader *r, const uint8_t *capdu, size_t clen, uint8_t *rsp, size_t *rsp_len, uint16_t *sw)
{
    uint8_t raw[300];
    size_t rl = sizeof raw;
    if (r->transmit(r->ctx, capdu, clen, raw, &rl) < 0 || rl < 2)
        return OPK_ERR_TRANSMIT;
    *sw = (uint16_t)(raw[rl - 2] << 8 | raw[rl - 1]);
    if ((*sw >> 8) == 0x61) {
        uint8_t gr[5] = {0x00, 0xC0, 0x00, 0x00, (uint8_t)*sw};
        rl = sizeof raw;
        if (r->transmit(r->ctx, gr, 5, raw, &rl) < 0 || rl < 2)
            return OPK_ERR_TRANSMIT;
        *sw = (uint16_t)(raw[rl - 2] << 8 | raw[rl - 1]);
    } else if ((*sw >> 8) == 0x6C) {
        uint8_t again[300];
        memcpy(again, capdu, clen);
        again[clen - 1] = (uint8_t)*sw;
        rl = sizeof raw;
        if (r->transmit(r->ctx, again, clen, raw, &rl) < 0 || rl < 2)
            return OPK_ERR_TRANSMIT;
        *sw = (uint16_t)(raw[rl - 2] << 8 | raw[rl - 1]);
    }
    if (rl - 2 > *rsp_len)
        return OPK_ERR_CARD;
    memcpy(rsp, raw, rl - 2);
    *rsp_len = rl - 2;
    return OPK_OK;
}

int opk_exchange(opk_session *s, const uint8_t *capdu, size_t clen)
{
    s->rsp_len = sizeof s->rsp;
    return opk_xchg(s->reader, capdu, clen, s->rsp, &s->rsp_len, &s->sw);
}

int opk_build_dol_tag(opk_session *s, uint32_t dol_tag, const uint8_t *fallback, size_t fallback_len, uint8_t *out,
                      size_t cap, size_t *out_len)
{
    size_t dl = 0;
    const uint8_t *d = opk_db_get(s->db, dol_tag, &dl);
    if (!d) {
        d = fallback;
        dl = fallback_len;
    }
    opk_session_sync(s);
    return opk_dol_build(d, dl, s->db, out, cap < OPK_MAX_COMMAND_DATA ? cap : OPK_MAX_COMMAND_DATA, out_len);
}

int opk_gpo(opk_session *s)
{
    uint8_t data[260], cmd[270];
    size_t n = opk_tlv_encode(0x83, s->pdol_data, s->pdol_len, data);
    size_t cl = opk_cmd(cmd, 0x80, 0xA8, 0x00, 0x00, data, n, 0);
    return opk_exchange(s, cmd, cl);
}

int opk_parse_gpo(opk_session *s)
{
    size_t pos = 0;
    opk_tlv t, extra;
    if (opk_tlv_next(s->rsp, s->rsp_len, &pos, &t) != 1 || opk_tlv_next(s->rsp, s->rsp_len, &pos, &extra) != 0)
        return OPK_ERR_CARD;
    if (t.tag == 0x80) {
        if (t.len < 2 || (t.len - 2) % 4)
            return OPK_ERR_CARD;
        opk_db_set(s->db, 0x82, t.val, 2);
        opk_db_set(s->db, 0x94, t.val + 2, t.len - 2);
        return OPK_OK;
    }
    if (t.tag == 0x77) {
        if (opk_tlv_store_card(s->db, t.val, t.len))
            return OPK_ERR_CARD;
        return opk_db_has(s->db, 0x82) ? OPK_OK : OPK_ERR_CARD;
    }
    return OPK_ERR_CARD;
}

/* ------------------------------------------------------------------ read application data */
static int store_record_dupcheck(opk_session *s, const uint8_t *buf, size_t len)
{
    size_t pos = 0;
    opk_tlv t;
    int r;
    while ((r = opk_tlv_next(buf, len, &pos, &t)) == 1) {
        if (opk_tlv_constructed(t.tag)) {
            if ((r = store_record_dupcheck(s, t.val, t.len)) != OPK_OK)
                return r;
            continue;
        }
        if (opk_tag_is_terminal(t.tag))
            continue; /* never let the card overwrite terminal data */
        if (opk_db_has(s->db, t.tag))
            return OPK_ERR_CARD;
        if (opk_db_set(s->db, t.tag, t.val, t.len))
            return OPK_ERR_FULL;
    }
    return r < 0 ? OPK_ERR_CARD : OPK_OK;
}

int opk_read_application_data(opk_session *s)
{
    size_t afl_len;
    const uint8_t *afl = opk_db_get(s->db, 0x94, &afl_len);
    uint8_t afl_copy[252];
    if (!afl)
        afl_len = 0;
    if (afl_len % 4 || afl_len > sizeof afl_copy)
        return OPK_ERR_CARD;
    if (afl_len)
        memcpy(afl_copy, afl, afl_len); /* memcpy(_, NULL, 0) is undefined behaviour */
    /* validate the whole AFL first, like the Python reference */
    for (size_t i = 0; i < afl_len; i += 4) {
        uint8_t sfi = afl_copy[i] >> 3, first = afl_copy[i + 1], last = afl_copy[i + 2], noda = afl_copy[i + 3];
        if (sfi < 1 || sfi > 30 || first == 0 || last < first || noda > last - first + 1 || (afl_copy[i] & 7))
            return OPK_ERR_CARD;
    }
    for (size_t i = 0; i < afl_len; i += 4) {
        uint8_t sfi = afl_copy[i] >> 3, first = afl_copy[i + 1], last = afl_copy[i + 2], noda = afl_copy[i + 3];
        for (int rec = first; rec <= last; rec++) {
            uint8_t cmd[5];
            size_t cl = opk_cmd(cmd, 0x00, 0xB2, (uint8_t)rec, (uint8_t)(sfi << 3 | 4), NULL, 0, 0);
            if (opk_exchange(s, cmd, cl))
                return OPK_ERR_TRANSMIT;
            if (s->sw != 0x9000)
                return OPK_ERR_CARD;
            if (opk_tlv_check(s->rsp, s->rsp_len))
                return OPK_ERR_CARD;
            size_t pos = 0;
            opk_tlv t, t2;
            int one = opk_tlv_next(s->rsp, s->rsp_len, &pos, &t) == 1;
            int single = one && opk_tlv_next(s->rsp, s->rsp_len, &pos, &t2) == 0;
            if (sfi <= 10 && !(single && t.tag == 0x70))
                return OPK_ERR_CARD;
            if (store_record_dupcheck(s, s->rsp, s->rsp_len))
                return OPK_ERR_CARD;
            if (rec - first < noda) {
                const uint8_t *src = NULL;
                size_t sl = 0;
                if (sfi <= 10) {
                    src = t.val;
                    sl = t.len;
                } else if (s->rsp_len && s->rsp[0] == 0x70) {
                    src = s->rsp;
                    sl = s->rsp_len;
                } else {
                    s->static_invalid = 1;
                }
                if (src) {
                    if (s->static_len + sl > sizeof s->static_data)
                        return OPK_ERR_FULL;
                    memcpy(s->static_data + s->static_len, src, sl);
                    s->static_len += sl;
                }
            }
        }
    }
    return OPK_OK;
}

int opk_check_mandatory(opk_session *s, const uint32_t *tags, int n)
{
    for (int i = 0; i < n; i++)
        if (!opk_db_has(s->db, tags[i]))
            return OPK_ERR_CARD;
    return OPK_OK;
}

int opk_static_data(opk_session *s, uint8_t *out, size_t cap, size_t *len)
{
    if (s->static_invalid || s->static_len > cap)
        return OPK_ERR_ODA;
    memcpy(out, s->static_data, s->static_len);
    *len = s->static_len;
    size_t tl;
    const uint8_t *taglist = opk_db_get(s->db, 0x9F4A, &tl);
    if (taglist && tl) {
        size_t al;
        const uint8_t *aip = opk_db_get(s->db, 0x82, &al);
        if (tl != 1 || taglist[0] != 0x82)
            return OPK_ERR_ODA;
        if (aip) {
            if (*len + al > cap)
                return OPK_ERR_ODA;
            memcpy(out + *len, aip, al);
            *len += al;
        }
    }
    return OPK_OK;
}

/* ------------------------------------------------------------------ ODA key chain */
int opk_retrieve_issuer_pk(opk_session *s, opk_pubkey *out)
{
    size_t l, il;
    const uint8_t *rid = opk_db_get(s->db, 0x4F, &l);
    if (!rid)
        rid = opk_db_get(s->db, 0x84, &l);
    const uint8_t *idx = opk_db_get(s->db, 0x8F, &il);
    if (!rid || l < 5 || !idx || !opk_db_has(s->db, 0x90) || !opk_db_has(s->db, 0x9F32))
        return OPK_ERR_ODA;
    const opk_capk *capk = opk_find_capk(s->env, rid, idx[0], s->txn->date);
    if (!capk)
        return OPK_ERR_ODA;
    return opk_oda_issuer_pk(capk, s->db, s->txn->date, out);
}

int opk_retrieve_icc_pk(opk_session *s, opk_pubkey *out)
{
    opk_pubkey issuer;
    uint8_t sd[OPK_STATIC_DATA_MAX + 8];
    size_t sdl, cl, rl = 0, el, pl;
    if (opk_retrieve_issuer_pk(s, &issuer))
        return OPK_ERR_ODA;
    const uint8_t *cert = opk_db_get(s->db, 0x9F46, &cl);
    const uint8_t *rem = opk_db_get(s->db, 0x9F48, &rl);
    const uint8_t *exp = opk_db_get(s->db, 0x9F47, &el);
    const uint8_t *pan = opk_db_get(s->db, 0x5A, &pl);
    if (!cert || !exp || !pan)
        return OPK_ERR_ODA;
    if (opk_static_data(s, sd, sizeof sd, &sdl))
        return OPK_ERR_ODA;
    return opk_oda_icc_pk(&issuer, cert, cl, rem, rem ? rl : 0, exp, el, sd, sdl, pan, pl, s->txn->date, out);
}

/* ------------------------------------------------------------------ processing restrictions */
int opk_processing_restrictions(opk_session *s)
{
    const opk_terminal_config *term = &s->env->terminal;
    opk_db *db = s->db;
    size_t l1, l2, al;
    const uint8_t *cv = opk_db_get(db, 0x9F08, &l1), *tv = opk_db_get(db, 0x9F09, &l2);
    if (cv && (l1 != l2 || memcmp(cv, tv, l1)))
        TVR(s, 2, 8);
    const uint8_t *auc = opk_db_get(db, 0x9F07, &al);
    if (auc && al >= 2) {
        uint8_t tt = s->txn->type;
        int is_atm = ((term->terminal_type & 0x0F) >= 4 && (term->terminal_type & 0x0F) <= 6) &&
                     (term->terminal_type >> 4) == 1 && BIT(term->additional_capabilities, 1, 8);
        if ((is_atm && !BIT(auc, 1, 2)) || (!is_atm && !BIT(auc, 1, 1)))
            TVR(s, 2, 5);
        size_t cl;
        const uint8_t *icc_country = opk_db_get(db, 0x5F28, &cl);
        if (icc_country) {
            int domestic = cl == 2 && !memcmp(icc_country, term->country_code, 2);
            if (tt == 0x01 || tt == 0x17) {
                if (!BIT(auc, 1, domestic ? 8 : 7))
                    TVR(s, 2, 5);
            } else if (tt == 0x00 || tt == 0x09) {
                int ok = domestic ? (BIT(auc, 1, 6) || BIT(auc, 1, 4)) : (BIT(auc, 1, 5) || BIT(auc, 1, 3));
                if (!ok)
                    TVR(s, 2, 5);
                if (tt == 0x09 && !BIT(auc, 2, domestic ? 8 : 7))
                    TVR(s, 2, 5);
            }
        }
    }
    long today = opk_yymmdd_str(s->txn->date);
    const uint8_t *d = opk_db_get(db, 0x5F25, &l1);
    if (d) {
        if (!opk_valid_date(d, l1))
            return OPK_ERR_CARD;
        if (opk_yymmdd(d) > today)
            TVR(s, 2, 6);
    }
    d = opk_db_get(db, 0x5F24, &l1);
    if (d) {
        if (!opk_valid_date(d, l1))
            return OPK_ERR_CARD;
        if (opk_yymmdd(d) < today)
            TVR(s, 2, 7);
    }
    d = opk_db_get(db, 0x5A, &l1);
    if (d && opk_pan_on_exception_file(s->env, d, l1))
        TVR(s, 1, 5);
    opk_session_sync(s);
    return OPK_OK;
}

/* ------------------------------------------------------------------ CVM */
static int cvm_supported(const uint8_t caps[3], uint8_t method)
{
    switch (method & 0x3F) {
    case 0x01: return BIT(caps, 2, 8);
    case 0x02: return BIT(caps, 2, 7);
    case 0x03: return BIT(caps, 2, 8) && BIT(caps, 2, 6);
    case 0x04: return BIT(caps, 2, 5);
    case 0x05: return BIT(caps, 2, 5) && BIT(caps, 2, 6);
    case 0x1E: return BIT(caps, 2, 6);
    case 0x1F: return BIT(caps, 2, 4);
    case 0x00: return 1;
    default: return 0;
    }
}

static int cvm_known(uint8_t code)
{
    return code <= 0x05 || code == 0x1E || code == 0x1F;
}

static int condition_ok(opk_session *s, uint8_t cond, uint32_t x, uint32_t y, const uint8_t caps[3], uint8_t method)
{
    uint8_t tt = s->txn->type;
    uint32_t amount = s->txn->amount;
    size_t l;
    const uint8_t *ccy = opk_db_get(s->db, 0x9F42, &l);
    int same_ccy = ccy && l == 2 && !memcmp(ccy, s->txn->currency_code, 2);
    int unattended = !opk_terminal_attended(&s->env->terminal);
    switch (cond) {
    case 0x00: return 1;
    case 0x01: return unattended && tt == 0x01;
    case 0x02: return tt != 0x01 && tt != 0x09 && tt != 0x17 && s->txn->amount_other == 0;
    case 0x03: return cvm_supported(caps, method);
    case 0x04: return !unattended && (tt == 0x01 || tt == 0x17);
    case 0x05: return tt == 0x09 || s->txn->amount_other > 0;
    case 0x06: case 0x07: case 0x08: case 0x09: {
        if (!same_ccy)
            return 0;
        uint32_t lim = (cond == 0x06 || cond == 0x07) ? x : y;
        return (cond == 0x06 || cond == 0x08) ? amount < lim : amount > lim;
    }
    default: return 0;
    }
}

static void set_results(opk_cvm_result *o, const uint8_t rule[2], uint8_t res)
{
    o->results[0] = rule[0];
    o->results[1] = rule[1];
    o->results[2] = res;
}

/* 1 = CVM done (o filled); 0 = this CVM failed */
static int perform_cvm(opk_session *s, uint8_t code, const uint8_t rule[2], opk_pin_fn perform, void *ctx,
                       opk_cvm_result *o)
{
    if (code == 0x1F) {
        set_results(o, rule, OPK_RESULT_SUCCESS);
        return 1;
    }
    if (code == 0x1E) {
        set_results(o, rule, OPK_RESULT_UNKNOWN);
        o->signature = 1;
        return 1;
    }
    if (code == 0x02) {
        if (perform(s, code, ctx) == OPK_RESULT_FAILED)
            return 0;
        TVR(s, 3, 3);
        set_results(o, rule, OPK_RESULT_UNKNOWN);
        o->online_pin = 1;
        return 1;
    }
    if (perform(s, code, ctx) == OPK_RESULT_SUCCESS) {
        int sig = code == 0x03 || code == 0x05;
        set_results(o, rule, sig ? OPK_RESULT_UNKNOWN : OPK_RESULT_SUCCESS);
        o->signature = sig;
        o->offline_pin = 1;
        return 1;
    }
    return 0;
}

void opk_cvm_list_processing(opk_session *s, const uint8_t caps[3], opk_pin_fn perform, void *ctx,
                             opk_cvm_result *o)
{
    memset(o, 0, sizeof *o);
    size_t l;
    if (!opk_bit(s->db, 0x82, 1, 5)) {
        memcpy(o->results, "\x3F\x00\x00", 3);
        return;
    }
    const uint8_t *list = opk_db_get(s->db, 0x8E, &l);
    if (!list || l < 10) {
        TVR(s, 1, 6);
        opk_session_sync(s);
        memcpy(o->results, "\x3F\x00\x00", 3);
        return;
    }
    uint8_t cvm[252];
    memcpy(cvm, list, l < sizeof cvm ? l : sizeof cvm);
    uint32_t x = (uint32_t)cvm[0] << 24 | cvm[1] << 16 | cvm[2] << 8 | cvm[3];
    uint32_t y = (uint32_t)cvm[4] << 24 | cvm[5] << 16 | cvm[6] << 8 | cvm[7];
    const uint8_t *last_failed = NULL;
    for (size_t i = 8; i + 1 < l; i += 2) {
        const uint8_t *rule = cvm + i;
        uint8_t method = rule[0], cond = rule[1], code = method & 0x3F;
        int apply_next = (method & 0x40) != 0;
        if (!condition_ok(s, cond, x, y, caps, method))
            continue;
        if (!cvm_known(code)) {
            TVR(s, 3, 7);
            if (apply_next)
                continue;
            goto fail_rule;
        }
        if (code == 0x00)
            goto fail_rule;
        if (!cvm_supported(caps, code)) {
            if (apply_next)
                continue;
            goto fail_rule;
        }
        if (perform_cvm(s, code, rule, perform, ctx, o)) {
            opk_session_sync(s);
            return;
        }
        last_failed = rule;
        if (apply_next)
            continue;
    fail_rule:
        TVR(s, 3, 8);
        set_results(o, rule, OPK_RESULT_FAILED);
        opk_session_sync(s);
        return;
    }
    TVR(s, 3, 8);
    set_results(o, last_failed ? last_failed : (const uint8_t *)"\x3F\x00", OPK_RESULT_FAILED);
    opk_session_sync(s);
}

/* ------------------------------------------------------------------ TRM */
static int get_data(opk_session *s, uint32_t tag, uint8_t *out, size_t *len)
{
    uint8_t cmd[5];
    size_t cl = opk_cmd(cmd, 0x80, 0xCA, (uint8_t)(tag >> 8), (uint8_t)tag, NULL, 0, 0);
    if (opk_exchange(s, cmd, cl) || s->sw != 0x9000)
        return 0;
    opk_tlv t;
    if (!s->rsp_len || opk_tlv_find(s->rsp, s->rsp_len, tag, &t) != 1)
        return 0;
    opk_db_set(s->db, tag, t.val, t.len);
    memcpy(out, t.val, t.len);
    *len = t.len;
    return 1;
}

void opk_terminal_risk_management(opk_session *s)
{
    const opk_aid_config *cfg = s->aid;
    uint32_t amount = s->txn->amount, floor = cfg->floor_limit;
    if (amount >= floor)
        TVR(s, 4, 8);
    if (opk_online_capable(&s->env->terminal) && amount < floor && cfg->target_percent) {
        uint8_t r;
        s->env->rng(s->env->rng_ctx, &r, 1);
        int rnd = r % 99 + 1;
        long pct;
        if (amount < cfg->threshold) {
            pct = cfg->target_percent;
        } else {
            long span = (long)floor - cfg->threshold;
            if (span < 1)
                span = 1;
            pct = cfg->target_percent +
                  (long)(cfg->max_target_percent - cfg->target_percent) * (long)(amount - cfg->threshold) / span;
        }
        if (rnd <= pct)
            TVR(s, 4, 5);
    }
    size_t l1, l2;
    const uint8_t *lcol = opk_db_get(s->db, 0x9F14, &l1), *ucol = opk_db_get(s->db, 0x9F23, &l2);
    if (lcol && ucol) {
        uint8_t lc = lcol[0], uc = ucol[0];
        uint8_t atc[8], last[8];
        size_t al, ll;
        int ok_atc = get_data(s, 0x9F36, atc, &al);
        int ok_last = ok_atc ? get_data(s, 0x9F13, last, &ll) : get_data(s, 0x9F13, last, &ll);
        if (!ok_atc || !ok_last) {
            TVR(s, 4, 7);
            TVR(s, 4, 6);
            TVR(s, 1, 6);
        } else {
            long a = 0, lo = 0;
            for (size_t i = 0; i < al; i++) a = a << 8 | atc[i];
            for (size_t i = 0; i < ll; i++) lo = lo << 8 | last[i];
            if (a <= lo) {
                TVR(s, 4, 7);
                TVR(s, 4, 6);
            } else {
                if (a - lo > lc) TVR(s, 4, 7);
                if (a - lo > uc) TVR(s, 4, 6);
            }
            if (lo == 0)
                TVR(s, 2, 4);
        }
    }
    TSI(s, 1, 4);
    opk_session_sync(s);
}

/* ------------------------------------------------------------------ TAA */
static int hit(const uint8_t tvr[5], const uint8_t *a, const uint8_t *b)
{
    for (int i = 0; i < 5; i++)
        if ((tvr[i] & a[i]) || (tvr[i] & b[i]))
            return 1;
    return 0;
}

static const uint8_t *iac(opk_session *s, uint32_t tag, const uint8_t *dflt)
{
    size_t l;
    const uint8_t *v = opk_db_get(s->db, tag, &l);
    return (v && l == 5) ? v : dflt;
}

static const uint8_t ZERO5[5] = {0}, FF5[5] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

int opk_terminal_action_analysis(opk_session *s, const uint8_t *tac_denial, const uint8_t *tac_online,
                                 const uint8_t *tac_default, int online_capable)
{
    opk_session_sync(s);
    if (hit(s->tvr, iac(s, 0x9F0E, ZERO5), tac_denial))
        return AC_AAC;
    if (s->txn->force_online && online_capable) {
        TVR(s, 4, 4);
        opk_session_sync(s);
        return AC_ARQC;
    }
    if (online_capable)
        return hit(s->tvr, iac(s, 0x9F0F, FF5), tac_online) ? AC_ARQC : AC_TC;
    return hit(s->tvr, iac(s, 0x9F0D, FF5), tac_default) ? AC_AAC : AC_TC;
}

int opk_default_action(opk_session *s, const uint8_t *tac_default)
{
    opk_session_sync(s);
    return hit(s->tvr, iac(s, 0x9F0D, FF5), tac_default) ? AC_AAC : AC_TC;
}

int opk_parse_generate_ac(opk_session *s, const uint8_t **children, size_t *children_len)
{
    size_t pos = 0;
    opk_tlv t, extra;
    *children = NULL;
    *children_len = 0;
    if (opk_tlv_check(s->rsp, s->rsp_len) || opk_tlv_next(s->rsp, s->rsp_len, &pos, &t) != 1 ||
        opk_tlv_next(s->rsp, s->rsp_len, &pos, &extra) != 0)
        return OPK_ERR_CARD;
    if (t.tag == 0x80) {
        if (t.len < 11)
            return OPK_ERR_CARD;
        opk_db_set(s->db, 0x9F27, t.val, 1);
        opk_db_set(s->db, 0x9F36, t.val + 1, 2);
        opk_db_set(s->db, 0x9F26, t.val + 3, 8);
        if (t.len > 11)
            opk_db_set(s->db, 0x9F10, t.val + 11, t.len - 11);
        return OPK_OK;
    }
    if (t.tag == 0x77) {
        size_t p2 = 0;
        opk_tlv c;
        int r;
        while ((r = opk_tlv_next(t.val, t.len, &p2, &c)) == 1)
            if (!opk_tag_is_terminal(c.tag) && !opk_tlv_constructed(c.tag))
                opk_db_set(s->db, c.tag, c.val, c.len);
        if (!opk_db_has(s->db, 0x9F27) || !opk_db_has(s->db, 0x9F36))
            return OPK_ERR_CARD;
        *children = t.val;
        *children_len = t.len;
        return OPK_OK;
    }
    return OPK_ERR_CARD;
}
