/* Contact EMV kernel (EMV Books 1-4).
 * SPDX-License-Identifier: Apache-2.0 */
#include "opk_internal.h"

typedef struct {
    const opk_contact_host *host;
} pin_ctx;

static int match_cfg(const opk_env *env, const uint8_t *aid, size_t len)
{
    for (int i = 0; i < env->aid_count; i++) {
        const opk_aid_config *c = &env->aids[i];
        if ((len == c->aid_len && !memcmp(aid, c->aid, len)) ||
            (c->partial_match && len >= c->aid_len && !memcmp(aid, c->aid, c->aid_len)))
            return i;
    }
    return -1;
}

static void make_candidate(opk_app_candidate *c, const uint8_t *aid, size_t aid_len, const uint8_t *node,
                           size_t node_len, int cfg)
{
    static const char hx[] = "0123456789ABCDEF";
    opk_tlv label, prio;
    memset(c, 0, sizeof *c);
    memcpy(c->aid, aid, aid_len);
    c->aid_len = (uint8_t)aid_len;
    if (opk_tlv_find(node, node_len, 0x50, &label) == 1) {
        size_t n = label.len < 16 ? label.len : 16;
        memcpy(c->label, label.val, n);
    } else {
        for (size_t i = 0; i < aid_len && i < 8; i++) {
            c->label[2 * i] = hx[aid[i] >> 4];
            c->label[2 * i + 1] = hx[aid[i] & 15];
        }
    }
    uint8_t p = (opk_tlv_find(node, node_len, 0x87, &prio) == 1 && prio.len) ? prio.val[0] : 0;
    c->priority = p & 0x0F;
    c->needs_confirmation = (p & 0x80) != 0;
    c->cfg_index = cfg;
}

/* Returns the number of candidates, or <0 on a card error (blocked card). */
static int pse(const opk_env *env, const opk_reader *rd, opk_app_candidate *cands)
{
    uint8_t cmd[32], rsp[300];
    size_t rl = sizeof rsp;
    uint16_t sw;
    size_t cl = opk_cmd_select(cmd, (const uint8_t *)"1PAY.SYS.DDF01", 14, 1);
    if (opk_xchg(rd, cmd, cl, rsp, &rl, &sw))
        return OPK_ERR_TRANSMIT;
    if (sw == 0x6A81)
        return OPK_ERR_CARD;
    if (sw != 0x9000 || opk_tlv_check(rsp, rl))
        return 0;
    opk_tlv sfi;
    if (opk_tlv_find(rsp, rl, 0x88, &sfi) != 1 || sfi.len != 1 || sfi.val[0] < 1 || sfi.val[0] > 30)
        return 0;
    uint8_t s = sfi.val[0];
    int n = 0;
    for (int rec = 1; rec < 256; rec++) {
        rl = sizeof rsp;
        cl = opk_cmd(cmd, 0x00, 0xB2, (uint8_t)rec, (uint8_t)(s << 3 | 4), NULL, 0, 0);
        if (opk_xchg(rd, cmd, cl, rsp, &rl, &sw))
            return OPK_ERR_TRANSMIT;
        if (sw == 0x6A83)
            break;
        if (sw != 0x9000 || opk_tlv_check(rsp, rl))
            return 0;
        size_t pos = 0;
        opk_tlv t70, e;
        if (opk_tlv_next(rsp, rl, &pos, &t70) != 1 || t70.tag != 0x70)
            return 0;
        pos = 0;
        while (opk_tlv_next(t70.val, t70.len, &pos, &e) == 1 && n < OPK_MAX_CANDIDATES) {
            opk_tlv aid;
            if (e.tag != 0x61 || opk_tlv_find(e.val, e.len, 0x4F, &aid) != 1)
                continue;
            int cfg = match_cfg(env, aid.val, aid.len);
            if (cfg >= 0)
                make_candidate(&cands[n++], aid.val, aid.len, e.val, e.len, cfg);
        }
    }
    return n;
}

static int list_of_aids(const opk_env *env, const opk_reader *rd, opk_app_candidate *cands)
{
    int n = 0;
    for (int i = 0; i < env->aid_count && n < OPK_MAX_CANDIDATES; i++) {
        const opk_aid_config *cfg = &env->aids[i];
        int first = 1;
        for (;;) {
            uint8_t cmd[32], rsp[300];
            size_t rl = sizeof rsp;
            uint16_t sw;
            size_t cl = opk_cmd_select(cmd, cfg->aid, cfg->aid_len, first);
            if (opk_xchg(rd, cmd, cl, rsp, &rl, &sw))
                return OPK_ERR_TRANSMIT;
            if (sw == 0x6A81 && first)
                return OPK_ERR_CARD;
            if (sw != 0x9000 && sw != 0x6283)
                break;
            size_t pos = 0;
            opk_tlv top, df;
            if (opk_tlv_check(rsp, rl) || opk_tlv_next(rsp, rl, &pos, &top) != 1 ||
                opk_tlv_find(top.val, top.len, 0x84, &df) != 1)
                break;
            if (sw == 0x9000) {
                int exact = df.len == cfg->aid_len && !memcmp(df.val, cfg->aid, df.len);
                if (exact) {
                    make_candidate(&cands[n++], df.val, df.len, top.val, top.len, i);
                    break;
                }
                if (cfg->partial_match && df.len >= cfg->aid_len && !memcmp(df.val, cfg->aid, cfg->aid_len) &&
                    n < OPK_MAX_CANDIDATES)
                    make_candidate(&cands[n++], df.val, df.len, top.val, top.len, i);
            }
            if (!cfg->partial_match || n >= OPK_MAX_CANDIDATES)
                break;
            first = 0;
        }
    }
    return n;
}

static void remove_cand(opk_app_candidate *c, int *n, int idx)
{
    for (int i = idx; i < *n - 1; i++)
        c[i] = c[i + 1];
    (*n)--;
}

/* ------------------------------------------------------------------ PIN */
static int enciphered_verify(opk_session *s, const uint8_t block8[8], uint8_t *cmd, size_t *cl)
{
    opk_pubkey key;
    size_t l;
    if (opk_db_has(s->db, 0x9F2D)) {
        opk_pubkey issuer;
        size_t cl2, rl = 0, el = 0, pl;
        if (opk_retrieve_issuer_pk(s, &issuer))
            return OPK_ERR_ODA;
        const uint8_t *cert = opk_db_get(s->db, 0x9F2D, &cl2);
        const uint8_t *rem = opk_db_get(s->db, 0x9F2F, &rl);
        const uint8_t *exp = opk_db_get(s->db, 0x9F2E, &el);
        const uint8_t *pan = opk_db_get(s->db, 0x5A, &pl);
        if (!exp) {
            exp = (const uint8_t *)"\x03";
            el = 1;
        }
        if (opk_oda_icc_pk(&issuer, cert, cl2, rem, rem ? rl : 0, exp, el, NULL, 0, pan, pl, s->txn->date, &key))
            return OPK_ERR_ODA;
    } else if (opk_retrieve_icc_pk(s, &key)) {
        return OPK_ERR_ODA;
    }
    uint8_t gc[5];
    size_t gl = opk_cmd(gc, 0x00, 0x84, 0x00, 0x00, NULL, 0, 0);
    if (opk_exchange(s, gc, gl))
        return OPK_ERR_TRANSMIT;
    if (s->sw != 0x9000 || s->rsp_len != 8)
        return OPK_ERR_CARD;
    uint8_t block[OPK_MAX_RSA_BYTES], enc[OPK_MAX_RSA_BYTES];
    block[0] = 0x7F;
    memcpy(block + 1, block8, 8);
    memcpy(block + 9, s->rsp, 8);
    s->env->rng(s->env->rng_ctx, block + 17, key.modulus_len - 17);
    if (opk_rsa_public(key.modulus, key.modulus_len, key.exponent, key.exponent_len, block, enc))
        return OPK_ERR_ODA;
    *cl = opk_cmd(cmd, 0x00, 0x20, 0x00, 0x88, enc, key.modulus_len, -1);
    (void)l;
    return OPK_OK;
}

static int perform_pin(opk_session *s, uint8_t method, void *vctx)
{
    const opk_contact_host *host = ((pin_ctx *)vctx)->host;
    const uint8_t *caps = s->env->terminal.capabilities;
    char pin[13];
    if (method == 0x02) {
        memset(pin, 0, sizeof pin);
        if (!host->enter_pin(host->ctx, 1, -1, pin)) {
            TVR(s, 3, 4);
            return OPK_RESULT_FAILED;
        }
        return OPK_RESULT_SUCCESS;
    }
    if (!BIT(caps, 2, 8) && !BIT(caps, 2, 5)) {
        TVR(s, 3, 5);
        return OPK_RESULT_FAILED;
    }
    int tries = -1;
    uint8_t cmd[300];
    size_t cl = opk_cmd(cmd, 0x80, 0xCA, 0x9F, 0x17, NULL, 0, 0);
    if (opk_exchange(s, cmd, cl))
        return OPK_RESULT_FAILED;
    if (s->sw == 0x9000) {
        opk_tlv t;
        if (opk_tlv_find(s->rsp, s->rsp_len, 0x9F17, &t) == 1 && t.len) {
            tries = t.val[0];
            if (tries == 0) {
                TVR(s, 3, 6);
                return OPK_RESULT_FAILED;
            }
        }
    }
    int enciphered = method == 0x04 || method == 0x05;
    for (;;) {
        memset(pin, 0, sizeof pin);
        if (!host->enter_pin(host->ctx, 0, tries, pin)) {
            TVR(s, 3, 4);
            return OPK_RESULT_FAILED;
        }
        size_t n = strlen(pin);
        if (n < 4 || n > 12)
            return OPK_RESULT_FAILED;
        uint8_t block[8];
        memset(block, 0xFF, 8);
        block[0] = (uint8_t)(0x20 | n);
        for (size_t i = 0; i < n; i++) {
            uint8_t d = (uint8_t)(pin[i] - '0');
            size_t nib = i + 2;
            block[nib / 2] = (nib & 1) ? (uint8_t)((block[nib / 2] & 0xF0) | d) : (uint8_t)((block[nib / 2] & 0x0F) | d << 4);
        }
        if (enciphered) {
            if (enciphered_verify(s, block, cmd, &cl))
                return OPK_RESULT_FAILED;
        } else {
            cl = opk_cmd(cmd, 0x00, 0x20, 0x00, 0x80, block, 8, -1);
        }
        if (opk_exchange(s, cmd, cl))
            return OPK_RESULT_FAILED;
        if (s->sw == 0x9000)
            return OPK_RESULT_SUCCESS;
        if ((s->sw >> 4) == 0x63C) {
            tries = s->sw & 0x0F;
            if (tries == 0) {
                TVR(s, 3, 6);
                return OPK_RESULT_FAILED;
            }
            continue;
        }
        if (s->sw == 0x6983 || s->sw == 0x6984) {
            TVR(s, 3, 6);
            return OPK_RESULT_FAILED;
        }
        return OPK_RESULT_FAILED;
    }
}

/* ------------------------------------------------------------------ ODA */
static int do_oda(opk_session *s, const uint8_t *aip, const uint8_t *caps)
{
    opk_pubkey icc, issuer;
    if (BIT(aip, 1, 1) && BIT(caps, 3, 4)) {
        TSI(s, 1, 8);
        if (opk_retrieve_icc_pk(s, &icc)) {
            TVR(s, 1, 3);
            opk_session_sync(s);
            return 0;
        }
        opk_session_sync(s);
        return 1;
    }
    if (BIT(aip, 1, 6) && BIT(caps, 3, 7)) {
        TSI(s, 1, 8);
        int ok = 0;
        if (!opk_retrieve_icc_pk(s, &icc)) {
            size_t dl;
            const uint8_t *ddol = opk_db_get(s->db, 0x9F49, &dl);
            if (!ddol || !dl) {
                ddol = s->aid->default_ddol;
                dl = s->aid->default_ddol_len;
            }
            uint8_t ddol_copy[64], data[256], cmd[270];
            size_t n;
            memcpy(ddol_copy, ddol, dl < sizeof ddol_copy ? dl : sizeof ddol_copy);
            opk_session_sync(s);
            if (opk_dol_contains(ddol_copy, dl, 0x9F37) &&
                !opk_dol_build(ddol_copy, dl, s->db, data, OPK_MAX_COMMAND_DATA, &n)) {
                size_t cl = opk_cmd(cmd, 0x00, 0x88, 0x00, 0x00, data, n, 0);
                if (opk_exchange(s, cmd, cl))
                    return OPK_ERR_TRANSMIT;
                opk_tlv t, sd;
                size_t pos = 0;
                if (s->sw == 0x9000 && !opk_tlv_check(s->rsp, s->rsp_len) &&
                    opk_tlv_next(s->rsp, s->rsp_len, &pos, &t) == 1) {
                    const uint8_t *sdad = NULL;
                    size_t sl = 0;
                    if (t.tag == 0x80) {
                        sdad = t.val;
                        sl = t.len;
                    } else if (opk_tlv_find(t.val, t.len, 0x9F4B, &sd) == 1) {
                        sdad = sd.val;
                        sl = sd.len;
                    }
                    uint8_t scratch[OPK_MAX_RSA_BYTES], sdad_copy[OPK_MAX_RSA_BYTES];
                    const uint8_t *dd;
                    size_t ddl;
                    if (sdad && sl <= sizeof sdad_copy) {
                        memcpy(sdad_copy, sdad, sl);
                        if (!opk_oda_verify_dynamic(&icc, sdad_copy, sl, data, n, scratch, &dd, &ddl)) {
                            opk_db_set(s->db, 0x9F4B, sdad_copy, sl);
                            opk_db_set(s->db, 0x9F4C, dd + 1, dd[0]);
                            ok = 1;
                        }
                    }
                }
            }
        }
        if (!ok)
            TVR(s, 1, 4);
        opk_session_sync(s);
        return 0;
    }
    if (BIT(aip, 1, 7) && BIT(caps, 3, 8)) {
        TSI(s, 1, 8);
        TVR(s, 1, 2);
        size_t sl, sdl;
        uint8_t sd[OPK_STATIC_DATA_MAX + 8];
        const uint8_t *ssad = opk_db_get(s->db, 0x93, &sl);
        uint8_t dac[2], ssad_copy[OPK_MAX_RSA_BYTES];
        int ok = ssad && sl <= sizeof ssad_copy && !opk_retrieve_issuer_pk(s, &issuer) &&
                 !opk_static_data(s, sd, sizeof sd, &sdl);
        if (ok) {
            memcpy(ssad_copy, ssad, sl);
            ok = !opk_oda_verify_sda(&issuer, ssad_copy, sl, sd, sdl, dac);
        }
        if (ok)
            opk_db_set(s->db, 0x9F45, dac, 2);
        else
            TVR(s, 1, 7);
        opk_session_sync(s);
        return 0;
    }
    TVR(s, 1, 8);
    opk_session_sync(s);
    return 0;
}

/* ------------------------------------------------------------------ GENERATE AC */
static int cid_allowed(int req, int got)
{
    if (got == AC_AAC) return 1;
    if (got == AC_ARQC) return req == AC_ARQC || req == AC_TC;
    if (got == AC_TC) return req == AC_TC;
    return 0;
}

/* Returns cid (>=0), -1 on CDA failure, or an opk_err (< -1) on a card error. */
static int generate_ac(opk_session *s, int ac, uint32_t cdol_tag, int cda, int first)
{
    size_t cdl, tl;
    const uint8_t *cdol_p = opk_db_get(s->db, cdol_tag, &cdl);
    uint8_t cdol[252];
    memcpy(cdol, cdol_p, cdl);
    if (opk_dol_contains(cdol, cdl, 0x98)) {
        uint8_t tdol_copy[64], tdd[256], h[20];
        size_t n;
        const uint8_t *tdol = opk_db_get(s->db, 0x97, &tl);
        if (!tdol) {
            tdol = NULL;
            tl = 0;
            /* default TDOL is not configured in this implementation */
        }
        memcpy(tdol_copy, tdol ? tdol : (const uint8_t *)"", tl);
        opk_session_sync(s);
        if (opk_dol_build(tdol_copy, tl, s->db, tdd, OPK_MAX_COMMAND_DATA, &n))
            return OPK_ERR_CARD;
        opk_sha1(tdd, n, h);
        opk_db_set(s->db, 0x98, h, 20);
    }
    uint8_t data[256];
    size_t dl;
    opk_session_sync(s);
    if (opk_dol_build(cdol, cdl, s->db, data, OPK_MAX_COMMAND_DATA, &dl))
        return OPK_ERR_CARD;
    if (first) {
        memcpy(s->cdol1_data, data, dl);
        s->cdol1_len = dl;
    }
    int use_cda = cda && ac != AC_AAC && !BIT(s->tvr, 1, 3);
    uint8_t cmd[270];
    size_t cl = opk_cmd(cmd, 0x80, 0xAE, (uint8_t)(ac | (use_cda ? AC_CDA : 0)), 0x00, data, dl, 0);
    if (opk_exchange(s, cmd, cl))
        return OPK_ERR_TRANSMIT;
    if (s->sw != 0x9000)
        return OPK_ERR_CARD;
    opk_db_del(s->db, 0x9F26);
    opk_db_del(s->db, 0x9F4B);
    opk_db_del(s->db, 0x9F27);
    const uint8_t *children;
    size_t children_len, l;
    if (opk_parse_generate_ac(s, &children, &children_len))
        return OPK_ERR_CARD;
    uint8_t cidb = opk_db_get(s->db, 0x9F27, &l)[0];
    int cid = cidb & 0xC0;
    if (!cid_allowed(ac, cid))
        return OPK_ERR_CARD;
    if (use_cda && cid != AC_AAC) {
        opk_pubkey icc;
        size_t sl, ul;
        const uint8_t *sdad = opk_db_get(s->db, 0x9F4B, &sl);
        if (opk_retrieve_icc_pk(s, &icc) || !sdad) {
            TVR(s, 1, 3);
            opk_session_sync(s);
            return -1;
        }
        uint8_t tx[1024], sdad_copy[OPK_MAX_RSA_BYTES], un[8], acv[8];
        size_t txl = 0, p = 0;
        memcpy(tx, s->pdol_data, s->pdol_len); txl += s->pdol_len;
        memcpy(tx + txl, s->cdol1_data, s->cdol1_len); txl += s->cdol1_len;
        if (!first) {
            memcpy(tx + txl, data, dl);
            txl += dl;
        }
        opk_tlv c;
        while (opk_tlv_next(children, children_len, &p, &c) == 1)
            if (c.tag != 0x9F4B && txl + c.raw_len <= sizeof tx) {
                memcpy(tx + txl, c.raw, c.raw_len);
                txl += c.raw_len;
            }
        memcpy(sdad_copy, sdad, sl);
        memcpy(un, opk_db_get(s->db, 0x9F37, &ul), 4);
        if (opk_oda_verify_cda(&icc, sdad_copy, sl, un, ul, cidb, tx, txl, acv)) {
            TVR(s, 1, 3);
            opk_session_sync(s);
            return -1;
        }
        opk_db_set(s->db, 0x9F26, acv, 8);
    } else if (!opk_db_has(s->db, 0x9F26)) {
        return OPK_ERR_CARD;
    }
    return cid;
}

/* ------------------------------------------------------------------ scripts */
static int run_scripts(opk_session *s, const uint8_t *scripts, size_t len, uint32_t which, uint8_t *res, size_t *rl)
{
    size_t pos = 0;
    opk_tlv tmpl;
    if (!scripts || !len)
        return OPK_OK;
    while (opk_tlv_next(scripts, len, &pos, &tmpl) == 1) {
        if (tmpl.tag != which)
            continue;
        opk_tlv sid, c;
        int has_sid = opk_tlv_find(tmpl.val, tmpl.len, 0x9F18, &sid) == 1;
        int seq = 0;
        uint8_t result = 0x20;
        size_t p = 0;
        while (opk_tlv_next(tmpl.val, tmpl.len, &p, &c) == 1) {
            if (c.tag != 0x86)
                continue;
            seq++;
            if (opk_exchange(s, c.val, c.len))
                return OPK_ERR_TRANSMIT;
            uint8_t sw1 = (uint8_t)(s->sw >> 8);
            if (sw1 != 0x90 && sw1 != 0x62 && sw1 != 0x63) {
                result = (uint8_t)(0x10 | (seq < 15 ? seq : 15));
                if (which == 0x71) TVR(s, 5, 6);
                else TVR(s, 5, 5);
                break;
            }
        }
        TSI(s, 1, 3);
        res[(*rl)++] = result;
        if (has_sid && sid.len == 4)
            memcpy(res + *rl, sid.val, 4);
        else
            memset(res + *rl, 0, 4);
        *rl += 4;
    }
    opk_session_sync(s);
    return OPK_OK;
}

/* ------------------------------------------------------------------ per application */
static void finish(opk_session *s, opk_outcome *out, opk_status st, opk_cvm cvm)
{
    opk_session_sync(s);
    opk_outcome_set(out, st, cvm, st == OPK_STATUS_APPROVED ? OPK_MSG_APPROVED : OPK_MSG_NOT_AUTHORISED);
}

/* Returns 1 = finished (out set), 0 = try another application, <0 = error */
static int process_app(opk_session *s, const opk_contact_host *host, const uint8_t *fci, size_t fl, opk_outcome *out)
{
    opk_db *db = s->db;
    size_t pos = 0, l;
    opk_tlv top, df;
    if (opk_tlv_check(fci, fl) || opk_tlv_next(fci, fl, &pos, &top) != 1 || top.tag != 0x6F ||
        opk_tlv_find(top.val, top.len, 0x84, &df) != 1)
        return OPK_ERR_CARD;
    opk_tlv_store_card(db, fci, fl);
    opk_db_set(db, 0x4F, df.val, df.len);
    opk_db_set(db, 0x9F06, s->aid->aid, s->aid->aid_len);

    if (opk_build_dol_tag(s, 0x9F38, (const uint8_t *)"", 0, s->pdol_data, sizeof s->pdol_data, &s->pdol_len))
        return OPK_ERR_CARD;
    if (opk_gpo(s))
        return OPK_ERR_TRANSMIT;
    if (s->sw == 0x6985)
        return 0;
    if (s->sw != 0x9000 || opk_tlv_check(s->rsp, s->rsp_len) || opk_parse_gpo(s))
        return OPK_ERR_CARD;
    int r = opk_read_application_data(s);
    if (r)
        return r == OPK_ERR_TRANSMIT ? r : OPK_ERR_CARD;
    static const uint32_t mand[] = {0x5F24, 0x5A, 0x8C, 0x8D};
    if (opk_check_mandatory(s, mand, 4))
        return OPK_ERR_CARD;
    uint8_t aip[2] = {0, 0};
    const uint8_t *aipv = opk_db_get(db, 0x82, &l);
    memcpy(aip, aipv, l < 2 ? l : 2); /* a short AIP reads as zero bits */
    const uint8_t *caps = s->env->terminal.capabilities;

    int cda = do_oda(s, aip, caps);
    if (cda < 0)
        return cda;
    if (opk_processing_restrictions(s))
        return OPK_ERR_CARD;

    pin_ctx pc = {host};
    opk_cvm_result cr;
    opk_cvm_list_processing(s, caps, perform_pin, &pc, &cr);
    opk_db_set(db, 0x9F34, cr.results, 3);
    if (BIT(aip, 1, 5))
        TSI(s, 1, 7);
    opk_session_sync(s);
    opk_cvm cvm = cr.online_pin ? OPK_CVM_ONLINE_PIN : cr.signature ? OPK_CVM_SIGNATURE
                  : cr.offline_pin ? OPK_CVM_OFFLINE_PIN : OPK_CVM_NO_CVM;

    if (BIT(aip, 1, 4) || s->txn->amount >= s->aid->floor_limit)
        opk_terminal_risk_management(s);

    int online_capable = opk_online_capable(&s->env->terminal);
    int ac = opk_terminal_action_analysis(s, s->aid->tac_denial, s->aid->tac_online, s->aid->tac_default,
                                          online_capable);
    int cid = generate_ac(s, ac, 0x8C, cda, 1);
    if (cid < -1)
        return cid;
    TSI(s, 1, 6);
    opk_session_sync(s);
    if (cid == -1) {
        finish(s, out, OPK_STATUS_DECLINED, cvm);
        return 1;
    }
    if (cid == AC_TC) {
        opk_db_set(db, 0x8A, (const uint8_t *)"Y1", 2);
        finish(s, out, OPK_STATUS_APPROVED, cvm);
        return 1;
    }
    if (cid == AC_AAC) {
        opk_db_set(db, 0x8A, (const uint8_t *)"Z1", 2);
        finish(s, out, OPK_STATUS_DECLINED, cvm);
        return 1;
    }

    /* online processing */
    opk_online_response rsp;
    memset(&rsp, 0, sizeof rsp);
    opk_session_sync(s);
    int online = host->go_online(host->ctx, db, &rsp);
    uint8_t results[64];
    size_t rl = 0;
    int final_ac;
    if (!online) {
        final_ac = opk_default_action(s, s->aid->tac_default);
        opk_db_set(db, 0x8A, (const uint8_t *)(final_ac == AC_TC ? "Y3" : "Z3"), 2);
    } else {
        opk_db_set(db, 0x8A, rsp.arc, 2);
        if (rsp.issuer_auth_data_len) {
            size_t c2l;
            opk_db_set(db, 0x91, rsp.issuer_auth_data, rsp.issuer_auth_data_len);
            const uint8_t *cdol2 = opk_db_get(db, 0x8D, &c2l);
            int cdol2_has_91 = opk_dol_contains(cdol2, c2l, 0x91);
            if (BIT(aip, 1, 3) && !cdol2_has_91) {
                uint8_t cmd[32];
                size_t cl = opk_cmd(cmd, 0x00, 0x82, 0x00, 0x00, rsp.issuer_auth_data, rsp.issuer_auth_data_len, -1);
                if (opk_exchange(s, cmd, cl))
                    return OPK_ERR_TRANSMIT;
                TSI(s, 1, 5);
                if (s->sw != 0x9000)
                    TVR(s, 5, 7);
            } else if (cdol2_has_91) {
                TSI(s, 1, 5);
            }
            opk_session_sync(s);
        }
        if (run_scripts(s, rsp.scripts, rsp.scripts_len, 0x71, results, &rl))
            return OPK_ERR_TRANSMIT;
        final_ac = rsp.approved ? AC_TC : AC_AAC;
    }
    int cid2 = generate_ac(s, final_ac, 0x8D, cda, 0);
    if (cid2 < -1)
        return cid2;
    if (online && run_scripts(s, rsp.scripts, rsp.scripts_len, 0x72, results, &rl))
        return OPK_ERR_TRANSMIT;
    if (rl)
        opk_db_set(db, 0x9F5B, results, rl);
    finish(s, out, cid2 == AC_TC ? OPK_STATUS_APPROVED : OPK_STATUS_DECLINED, cvm);
    return 1;
}

static int contact_process(const opk_env *env, const opk_transaction *txn, const opk_reader *reader,
                           const opk_contact_host *host, opk_outcome *out, opk_db *db)
{
    opk_app_candidate cands[OPK_MAX_CANDIDATES];
    opk_db_init(db);
    int n = pse(env, reader, cands);
    if (n == 0)
        n = list_of_aids(env, reader, cands);
    if (n < 0) {
        opk_outcome_end(out, OPK_L2_CARD_DATA_ERROR, 0, OPK_MSG_PROCESSING_ERROR);
        return n == OPK_ERR_TRANSMIT ? n : OPK_OK;
    }
    /* stable sort by priority, 0 (none) last */
    for (int i = 1; i < n; i++) {
        opk_app_candidate t = cands[i];
        int j = i - 1;
        while (j >= 0) {
            int a0 = cands[j].priority == 0, b0 = t.priority == 0;
            int greater = a0 != b0 ? a0 > b0 : cands[j].priority > t.priority;
            if (!greater)
                break;
            cands[j + 1] = cands[j];
            j--;
        }
        cands[j + 1] = t;
    }
    opk_session sess;
    while (n > 0) {
        int idx = 0;
        if (!(n == 1 && !cands[0].needs_confirmation)) {
            idx = host->choose_application(host->ctx, cands, n);
            if (idx < 0 || idx >= n)
                break;
        }
        uint8_t cmd[32], fci[300];
        size_t fl = sizeof fci;
        uint16_t sw;
        size_t cl = opk_cmd_select(cmd, cands[idx].aid, cands[idx].aid_len, 1);
        if (opk_xchg(reader, cmd, cl, fci, &fl, &sw))
            return OPK_ERR_TRANSMIT;
        if (sw != 0x9000) {
            remove_cand(cands, &n, idx);
            continue;
        }
        opk_session_init(&sess, env, &env->aids[cands[idx].cfg_index], txn, reader, db);
        int r = process_app(&sess, host, fci, fl, out);
        if (r == 1)
            return OPK_OK;
        if (r == 0) {
            remove_cand(cands, &n, idx);
            continue;
        }
        opk_session_sync(&sess);
        opk_outcome_end(out, OPK_L2_CARD_DATA_ERROR, sess.sw, OPK_MSG_PROCESSING_ERROR);
        return r == OPK_ERR_TRANSMIT ? r : OPK_OK;
    }
    opk_outcome_end(out, OPK_L2_EMPTY_CANDIDATE_LIST, 0, OPK_MSG_PROCESSING_ERROR);
    return OPK_OK;
}

int opk_contact_process(const opk_env *env, const opk_transaction *txn, const opk_reader *reader,
                        const opk_contact_host *host, opk_outcome *out, opk_db *db)
{
    int r = contact_process(env, txn, reader, host, out, db);
    if (r == OPK_ERR_TRANSMIT) { /* card removed, timeout, ... (Level 1) */
        opk_outcome_end(out, OPK_L2_OK, 0, OPK_MSG_PROCESSING_ERROR);
        out->l1_error = 2;
    }
    return r;
}
