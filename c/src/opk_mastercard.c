/* Kernel 2: Mastercard (EMV Contactless Book C-2), EMV mode.
 * SPDX-License-Identifier: Apache-2.0 */
#include "opk_internal.h"

static void select_next(opk_outcome *o, opk_l2_error l2, uint16_t sw)
{
    opk_outcome_set(o, OPK_STATUS_SELECT_NEXT, OPK_CVM_NA, OPK_MSG_NA);
    o->start = 2;
    o->l2_error = l2;
    o->sw12 = sw;
}

static void final(opk_session *s, opk_outcome *o, opk_status st, opk_cvm cvm, opk_l2_error l2)
{
    opk_session_sync(s);
    opk_message m = st == OPK_STATUS_APPROVED ? (cvm == OPK_CVM_SIGNATURE ? OPK_MSG_APPROVED_SIGN : OPK_MSG_APPROVED)
                    : st == OPK_STATUS_DECLINED ? OPK_MSG_NOT_AUTHORISED : OPK_MSG_AUTHORISING;
    opk_outcome_set(o, st, cvm, m);
    o->l2_error = l2;
}

static int no_pin(opk_session *s, uint8_t method, void *ctx)
{
    (void)s; (void)method; (void)ctx;
    return OPK_RESULT_UNKNOWN;
}

static int64_t tag_amount(const opk_db *db, uint32_t tag, int64_t dflt)
{
    size_t l;
    const uint8_t *v = opk_db_get(db, tag, &l);
    return v ? opk_bcd_to_int(v, l) : dflt;
}

int opk_kernel_mastercard(const opk_kernel_ctx *k, opk_outcome *out)
{
    opk_session sess;
    opk_session *s = &sess;
    opk_db *db = k->db;
    const opk_aid_config *cfg = k->aid;
    opk_session_init(s, k->env, cfg, k->txn, k->reader, db);

    size_t pos = 0, l;
    opk_tlv top;
    if (opk_tlv_check(k->fci, k->fci_len)) {
        opk_outcome_end(out, OPK_L2_PARSING_ERROR, 0, OPK_MSG_PROCESSING_ERROR);
        return OPK_OK;
    }
    if (opk_tlv_next(k->fci, k->fci_len, &pos, &top) != 1 || top.tag != 0x6F) {
        select_next(out, OPK_L2_PARSING_ERROR, 0);
        return OPK_OK;
    }
    opk_tlv_store_card(db, k->fci, k->fci_len);
    opk_db_set(db, 0x9F06, k->adf_name, k->adf_len);
    uint8_t kc = 0x20;
    const uint8_t *v = opk_db_get(db, 0xDF811B, &l);
    if (v && l)
        kc = v[0];

    /* 1. GPO */
    if (opk_build_dol_tag(s, 0x9F38, NULL, 0, s->pdol_data, sizeof s->pdol_data, &s->pdol_len))
        goto card_error;
    if (opk_gpo(s))
        return OPK_ERR_TRANSMIT;
    if (s->sw != 0x9000) {
        select_next(out, OPK_L2_STATUS_BYTES, s->sw);
        return OPK_OK;
    }
    if (opk_tlv_check(s->rsp, s->rsp_len) || opk_parse_gpo(s))
        goto card_error;
    uint8_t aip[2];
    memcpy(aip, opk_db_get(db, 0x82, &l), 2);
    if (!(BIT(aip, 2, 8) && !((kc >> 6) & 1))) {
        opk_outcome_end(out, OPK_L2_MAGSTRIPE_NOT_SUPPORTED, 0, OPK_MSG_INSERT_SWIPE_OR_TRY_ANOTHER);
        return OPK_OK;
    }

    /* 2. read records */
    if (!opk_db_get(db, 0x94, &l) || !l)
        goto card_error;
    int r = opk_read_application_data(s);
    if (r == OPK_ERR_TRANSMIT)
        return r;
    static const uint32_t mand[] = {0x5F24, 0x5A, 0x8C, 0x8D};
    if (r || opk_check_mandatory(s, mand, 4))
        goto card_error;

    /* 3. ODA: CDA only */
    uint8_t secap = 0x08;
    v = opk_db_get(db, 0xDF811F, &l);
    if (v && l)
        secap = v[0];
    int cda = BIT(aip, 1, 1) && ((secap >> 3) & 1);
    if (!cda) {
        TVR(s, 1, 8);
    } else {
        size_t il;
        const uint8_t *idx = opk_db_get(db, 0x8F, &il);
        const uint8_t *adf = opk_db_get(db, 0x9F06, &l);
        if (!idx || !opk_find_capk(k->env, adf, idx[0], k->txn->date))
            TVR(s, 1, 3);
    }
    opk_session_sync(s);

    /* 4. processing restrictions */
    if (opk_processing_restrictions(s))
        goto card_error;

    /* 5. CVM */
    int64_t amount = k->txn->amount;
    int64_t cvm_limit = cfg->cvm_required_limit >= 0 ? cfg->cvm_required_limit : tag_amount(db, 0xDF8126, 0);
    int on_device = BIT(aip, 1, 2) && ((kc >> 5) & 1);
    opk_cvm cvm;
    if (on_device && amount > cvm_limit) {
        opk_db_set(db, 0x9F34, (const uint8_t *)"\x01\x00\x02", 3);
        cvm = OPK_CVM_CONFIRMATION_CODE_VERIFIED;
    } else {
        uint8_t caps[3] = {0};
        v = opk_db_get(db, 0x9F33, &l);
        if (v && l == 3)
            memcpy(caps, v, 3);
        v = opk_db_get(db, amount > cvm_limit ? 0xDF8118 : 0xDF8119, &l);
        caps[1] = v && l ? v[0] : 0x08;
        opk_db_set(db, 0x9F33, caps, 3);
        opk_cvm_result res;
        opk_cvm_list_processing(s, caps, no_pin, NULL, &res);
        opk_db_set(db, 0x9F34, res.results, 3);
        cvm = res.online_pin ? OPK_CVM_ONLINE_PIN : res.signature ? OPK_CVM_SIGNATURE : OPK_CVM_NO_CVM;
    }

    /* 6. limits + floor */
    int64_t limit = on_device ? cfg->cl_transaction_limit_cdcvm : cfg->cl_transaction_limit;
    if (limit < 0)
        limit = tag_amount(db, on_device ? 0xDF8125 : 0xDF8124, -1);
    if (limit >= 0 && amount > limit) {
        select_next(out, OPK_L2_MAX_LIMIT_EXCEEDED, 0);
        return OPK_OK;
    }
    int64_t floor = tag_amount(db, 0xDF8123, cfg->floor_limit);
    if (amount > floor)
        TVR(s, 4, 8);
    opk_session_sync(s);

    /* 7. TAA */
    const uint8_t *tdef = opk_db_get(db, 0xDF8120, &l);
    const uint8_t *tden = opk_db_get(db, 0xDF8121, &l);
    const uint8_t *tonl = opk_db_get(db, 0xDF8122, &l);
    uint8_t tac_default[5], tac_denial[5], tac_online[5];
    memcpy(tac_default, tdef ? tdef : cfg->tac_default, 5);
    memcpy(tac_denial, tden ? tden : cfg->tac_denial, 5);
    memcpy(tac_online, tonl ? tonl : cfg->tac_online, 5);
    int ac = opk_terminal_action_analysis(s, tac_denial, tac_online, tac_default,
                                          opk_online_capable(&k->env->terminal));

    /* 8. GENERATE AC */
    int request_cda = cda && !BIT(s->tvr, 1, 3) && ac != AC_AAC;
    if (opk_build_dol_tag(s, 0x8C, NULL, 0, s->cdol1_data, sizeof s->cdol1_data, &s->cdol1_len))
        goto card_error;
    uint8_t cmd[270];
    size_t cl = opk_cmd(cmd, 0x80, 0xAE, (uint8_t)(ac | (request_cda ? AC_CDA : 0)), 0x00, s->cdol1_data,
                        s->cdol1_len, 0);
    if (opk_exchange(s, cmd, cl))
        return OPK_ERR_TRANSMIT;
    if (s->sw != 0x9000) {
        opk_outcome_end(out, OPK_L2_STATUS_BYTES, s->sw, OPK_MSG_PROCESSING_ERROR);
        return OPK_OK;
    }
    const uint8_t *children;
    size_t children_len;
    if (opk_parse_generate_ac(s, &children, &children_len))
        goto card_error;
    int cid = opk_db_get(db, 0x9F27, &l)[0] & 0xC0;

    if (request_cda && cid != AC_AAC) {
        size_t sl;
        const uint8_t *sdad = opk_db_get(db, 0x9F4B, &sl);
        opk_pubkey icc;
        if (!sdad || opk_retrieve_icc_pk(s, &icc)) {
            TVR(s, 1, 3);
            final(s, out, OPK_STATUS_DECLINED, cvm, OPK_L2_CAM_FAILED);
            return OPK_OK;
        }
        /* PDOL data || CDOL1 data || response TLVs other than 9F4B */
        uint8_t tx[1024];
        size_t tl = 0, p = 0;
        memcpy(tx, s->pdol_data, s->pdol_len); tl += s->pdol_len;
        memcpy(tx + tl, s->cdol1_data, s->cdol1_len); tl += s->cdol1_len;
        opk_tlv c;
        while (opk_tlv_next(children, children_len, &p, &c) == 1)
            if (c.tag != 0x9F4B && tl + c.raw_len <= sizeof tx) {
                memcpy(tx + tl, c.raw, c.raw_len);
                tl += c.raw_len;
            }
        uint8_t acv[8], un[8];
        size_t ul;
        memcpy(un, opk_db_get(db, 0x9F37, &ul), 4);
        uint8_t sdad_copy[OPK_MAX_RSA_BYTES];
        memcpy(sdad_copy, sdad, sl);
        if (opk_oda_verify_cda(&icc, sdad_copy, sl, un, ul, (uint8_t)opk_db_get(db, 0x9F27, &l)[0], tx, tl, acv)) {
            TVR(s, 1, 3);
            final(s, out, OPK_STATUS_DECLINED, cvm, OPK_L2_CAM_FAILED);
            return OPK_OK;
        }
        opk_db_set(db, 0x9F26, acv, 8);
    } else if (!opk_db_has(db, 0x9F26)) {
        goto card_error;
    }
    final(s, out, cid == AC_TC ? OPK_STATUS_APPROVED : cid == AC_ARQC ? OPK_STATUS_ONLINE_REQUEST
                                                                         : OPK_STATUS_DECLINED,
          cvm, OPK_L2_OK);
    return OPK_OK;

card_error:
    opk_outcome_end(out, OPK_L2_CARD_DATA_ERROR, 0, OPK_MSG_PROCESSING_ERROR);
    return OPK_OK;
}
