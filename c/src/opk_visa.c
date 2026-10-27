/* Kernel 3: Visa qVSDC (EMV Contactless Book C-3).
 * SPDX-License-Identifier: Apache-2.0 */
#include "opk_internal.h"

static void select_next(opk_outcome *o, opk_l2_error l2, uint16_t sw)
{
    opk_outcome_set(o, OPK_STATUS_SELECT_NEXT, OPK_CVM_NA, OPK_MSG_NA);
    o->start = 2;
    o->l2_error = l2;
    o->sw12 = sw;
}

static void tai(opk_outcome *o)
{
    opk_outcome_set(o, OPK_STATUS_TRY_ANOTHER_INTERFACE, OPK_CVM_NA, OPK_MSG_INSERT_CARD);
    o->alt_interface_contact = 1;
}

static void final(opk_session *s, opk_outcome *o, opk_status st, opk_cvm cvm)
{
    opk_session_sync(s);
    opk_message m = st == OPK_STATUS_APPROVED ? (cvm == OPK_CVM_SIGNATURE ? OPK_MSG_APPROVED_SIGN : OPK_MSG_APPROVED)
                    : st == OPK_STATUS_DECLINED ? OPK_MSG_NOT_AUTHORISED : OPK_MSG_AUTHORISING;
    opk_outcome_set(o, st, cvm, m);
}

static int cid_from_iad(const uint8_t *iad, size_t l)
{
    if (!iad || l < 5)
        return -1;
    switch ((iad[4] >> 4) & 3) {
    case 0: return AC_AAC;
    case 1: return AC_TC;
    case 2: return AC_ARQC;
    default: return -1;
    }
}

/* Track 2 digits before the separator must equal the PAN without F padding. */
static int track2_matches_pan(const uint8_t *t2, size_t tl, const uint8_t *pan, size_t pl)
{
    static const char hx[] = "0123456789ABCDEF";
    char a[40], b[24];
    size_t n = 0, m = 0;
    if (!t2 || !pan)
        return 1;
    for (size_t i = 0; i < tl && n + 2 < sizeof a; i++) {
        a[n++] = hx[t2[i] >> 4];
        a[n++] = hx[t2[i] & 15];
    }
    a[n] = 0;
    char *d = strchr(a, 'D');
    if (d)
        *d = 0;
    for (size_t i = 0; i < pl && m + 2 < sizeof b; i++) {
        b[m++] = hx[pan[i] >> 4];
        b[m++] = hx[pan[i] & 15];
    }
    while (m && b[m - 1] == 'F')
        m--;
    b[m] = 0;
    return !strcmp(a, b);
}

static void pan_from_track2(const uint8_t *t2, size_t tl, uint8_t *pan, size_t *pl)
{
    size_t n = 0;
    uint8_t nib[40];
    for (size_t i = 0; i < tl * 2 && n < sizeof nib; i++) {
        uint8_t x = (i & 1) ? (t2[i / 2] & 15) : (t2[i / 2] >> 4);
        if (x == 0xD)
            break;
        nib[n++] = x;
    }
    if (n & 1)
        nib[n++] = 0xF;
    for (size_t i = 0; i < n / 2; i++)
        pan[i] = (uint8_t)(nib[2 * i] << 4 | nib[2 * i + 1]);
    *pl = n / 2;
}

static int fdda(opk_session *s)
{
    size_t sl, cl;
    const uint8_t *sdad = opk_db_get(s->db, 0x9F4B, &sl);
    if (!sdad)
        return OPK_ERR_ODA;
    opk_pubkey icc;
    if (opk_retrieve_icc_pk(s, &icc))
        return OPK_ERR_ODA;
    uint8_t tdd[64];
    size_t tl = 0, l;
    const uint8_t *v = opk_db_get(s->db, 0x9F37, &l);
    memcpy(tdd, v, l);
    tl = l;
    const uint8_t *cad = opk_db_get(s->db, 0x9F69, &cl);
    if (cad && cl && cad[0] == 0x01 && cl < 32) {
        v = opk_db_get(s->db, 0x9F02, &l); memcpy(tdd + tl, v, l); tl += l;
        v = opk_db_get(s->db, 0x5F2A, &l); memcpy(tdd + tl, v, l); tl += l;
        memcpy(tdd + tl, cad, cl); tl += cl;
    }
    uint8_t scratch[OPK_MAX_RSA_BYTES];
    const uint8_t *dd;
    size_t ddl;
    if (opk_oda_verify_dynamic(&icc, sdad, sl, tdd, tl, scratch, &dd, &ddl))
        return OPK_ERR_ODA;
    opk_db_set(s->db, 0x9F4C, dd + 1, dd[0]);
    return OPK_OK;
}

/* Book C-3 5.6. Returns the CVM, or -1 when no CVM can be performed (decline). */
static int cvm(opk_session *s, const uint8_t *ttq, const uint8_t *ctq, int cid)
{
    if (!BIT(ttq, 2, 7))
        return OPK_CVM_NO_CVM;
    if (ctq) {
        if (BIT(ctq, 1, 8) && BIT(ttq, 1, 3))
            return OPK_CVM_ONLINE_PIN;
        if (BIT(ctq, 2, 8)) {
            size_t l;
            const uint8_t *cad = opk_db_get(s->db, 0x9F69, &l);
            if (cad && l >= 7 && memcmp(cad + 5, ctq, 2))
                return -1;
            return OPK_CVM_CONFIRMATION_CODE_VERIFIED;
        }
        if (BIT(ctq, 1, 7) && BIT(ttq, 1, 2))
            return OPK_CVM_SIGNATURE;
        return -1;
    }
    if (BIT(ttq, 1, 2))
        return OPK_CVM_SIGNATURE;
    if (BIT(ttq, 1, 3) && cid == AC_ARQC)
        return OPK_CVM_ONLINE_PIN;
    return -1;
}

int opk_kernel_visa(const opk_kernel_ctx *k, opk_outcome *out)
{
    opk_session sess;
    opk_session *s = &sess;
    opk_db *db = k->db;
    opk_session_init(s, k->env, k->aid, k->txn, k->reader, db);

    size_t pos = 0;
    opk_tlv top;
    if (opk_tlv_check(k->fci, k->fci_len)) {
        opk_outcome_end(out, OPK_L2_PARSING_ERROR, 0, OPK_MSG_NA);
        return OPK_OK;
    }
    if (opk_tlv_next(k->fci, k->fci_len, &pos, &top) != 1 || top.tag != 0x6F) {
        select_next(out, OPK_L2_PARSING_ERROR, 0);
        return OPK_OK;
    }
    opk_tlv_store_card(db, k->fci, k->fci_len);
    opk_db_set(db, 0x9F06, k->adf_name, k->adf_len);
    uint8_t ttq[4];
    memcpy(ttq, k->has_ttq ? k->ttq : k->aid->ttq, 4);
    opk_db_set(db, 0x9F66, ttq, 4);

    size_t pl;
    const uint8_t *pdol = opk_db_get(db, 0x9F38, &pl);
    if (!pdol || !pl || !opk_dol_contains(pdol, pl, 0x9F66)) {
        opk_outcome_end(out, OPK_L2_CARD_DATA_MISSING, 0, OPK_MSG_INSERT_SWIPE_OR_TRY_ANOTHER);
        return OPK_OK;
    }
    if (opk_build_dol_tag(s, 0x9F38, NULL, 0, s->pdol_data, sizeof s->pdol_data, &s->pdol_len))
        goto card_error;
    if (opk_gpo(s))
        return OPK_ERR_TRANSMIT;
    if (s->sw == 0x6984) { tai(out); return OPK_OK; }
    if (s->sw == 0x6985) { select_next(out, OPK_L2_STATUS_BYTES, s->sw); return OPK_OK; }
    if (s->sw == 0x6986) {
        opk_outcome_set(out, OPK_STATUS_TRY_AGAIN, OPK_CVM_NA, OPK_MSG_SEE_PHONE);
        out->start = 1;
        out->field_off_ms = 1300;
        return OPK_OK;
    }
    if (s->sw != 0x9000) {
        opk_outcome_end(out, OPK_L2_STATUS_BYTES, s->sw, OPK_MSG_NA);
        return OPK_OK;
    }
    if (!s->rsp_len || s->rsp[0] != 0x77 || opk_tlv_check(s->rsp, s->rsp_len) || opk_parse_gpo(s))
        goto card_error;

    size_t afl_len;
    if (opk_db_get(db, 0x94, &afl_len) && afl_len) {
        int r = opk_read_application_data(s);
        if (r == OPK_ERR_TRANSMIT)
            return r;
        if (r)
            goto card_error;
    }

    size_t l;
    size_t cl2;
    const uint8_t *cidv = opk_db_get(db, 0x9F27, &cl2);
    const uint8_t *iad = opk_db_get(db, 0x9F10, &l);
    if (cidv && cl2 < 1)
        goto card_error;
    int cid = cidv ? (cidv[0] & 0xC0) : cid_from_iad(iad, l);
    if (cid != AC_AAC && cid != AC_TC && cid != AC_ARQC)
        goto card_error;
    uint32_t mand[5] = {0x82, 0x9F36, 0x9F10};
    int nm = 3;
    if (cid != AC_AAC) mand[nm++] = 0x9F26;
    if (!opk_db_has(db, 0x57) && !opk_db_has(db, 0x5A)) mand[nm++] = 0x57;
    if (opk_check_mandatory(s, mand, nm))
        goto card_error;
    size_t t2l, panl;
    const uint8_t *t2 = opk_db_get(db, 0x57, &t2l), *pan = opk_db_get(db, 0x5A, &panl);
    if (!track2_matches_pan(t2, t2l, pan, panl))
        goto card_error;

    int online_capable = opk_online_capable(&k->env->terminal) && !BIT(ttq, 1, 4);
    size_t ctql;
    const uint8_t *ctq = opk_db_get(db, 0x9F6C, &ctql);
    int c = cvm(s, ttq, ctq, cid);
    if (c < 0) {
        final(s, out, OPK_STATUS_DECLINED, OPK_CVM_NO_CVM);
        return OPK_OK;
    }
    opk_cvm cv = (opk_cvm)c;
    if (cid == AC_AAC) { final(s, out, OPK_STATUS_DECLINED, cv); return OPK_OK; }
    if (cid == AC_ARQC) { final(s, out, OPK_STATUS_ONLINE_REQUEST, cv); return OPK_OK; }
    if (cv == OPK_CVM_ONLINE_PIN) {
        final(s, out, online_capable ? OPK_STATUS_ONLINE_REQUEST : OPK_STATUS_DECLINED, cv);
        return OPK_OK;
    }
    int failed = 0;
    const uint8_t *exp = opk_db_get(db, 0x5F24, &l);
    if (exp) {
        if (!opk_valid_date(exp, l))
            goto card_error;
        if (opk_yymmdd(exp) < opk_yymmdd_str(k->txn->date))
            failed = 1;
    }
    if (!failed) {
        uint8_t p2[12];
        size_t p2l = 0;
        if (pan) {
            failed = opk_pan_on_exception_file(k->env, pan, panl);
        } else if (t2) {
            pan_from_track2(t2, t2l, p2, &p2l);
            failed = opk_pan_on_exception_file(k->env, p2, p2l);
        }
    }
    if (!failed && !opk_bit(db, 0x82, 1, 6))
        failed = 1;
    if (!failed && fdda(s))
        failed = 1;
    if (!failed) {
        final(s, out, OPK_STATUS_APPROVED, cv);
        return OPK_OK;
    }
    /* offline transaction failed a check (Book C-3) */
    if (ctq && BIT(ctq, 1, 6) && online_capable)
        final(s, out, OPK_STATUS_ONLINE_REQUEST, cv);
    else if (ctq && BIT(ctq, 1, 5) && BIT(ttq, 1, 5))
        tai(out);
    else
        final(s, out, OPK_STATUS_DECLINED, cv);
    return OPK_OK;

card_error:
    opk_outcome_end(out, OPK_L2_CARD_DATA_ERROR, 0, OPK_MSG_NA);
    return OPK_OK;
}
