/* Kernel 2: Mastercard (EMV Contactless Book C-2), EMV mode.
 * SPDX-License-Identifier: Apache-2.0 */
#include "opk_internal.h"

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

    size_t l;
    int fr = opk_k_store_fci(s, k);
    if (fr < 0) {
        opk_outcome_end(out, OPK_L2_PARSING_ERROR, 0, OPK_MSG_PROCESSING_ERROR);
        return OPK_OK;
    }
    if (fr == 0) {
        opk_k_select_next(out, OPK_L2_PARSING_ERROR, 0);
        return OPK_OK;
    }
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
        opk_k_select_next(out, OPK_L2_STATUS_BYTES, s->sw);
        return OPK_OK;
    }
    if (opk_tlv_check(s->rsp, s->rsp_len) || opk_parse_gpo(s))
        goto card_error;
    uint8_t aip[2] = {0, 0};
    v = opk_db_get(db, 0x82, &l);
    memcpy(aip, v, l < 2 ? l : 2); /* a short AIP reads as zero bits */
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
    int cda = opk_k_select_cda(s, aip, (secap >> 3) & 1);

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
        opk_cvm_list_processing(s, caps, opk_k_no_pin, NULL, &res);
        opk_db_set(db, 0x9F34, res.results, 3);
        cvm = res.online_pin ? OPK_CVM_ONLINE_PIN : res.signature ? OPK_CVM_SIGNATURE : OPK_CVM_NO_CVM;
    }

    /* 6. limits + floor */
    int64_t limit = on_device ? cfg->cl_transaction_limit_cdcvm : cfg->cl_transaction_limit;
    if (limit < 0)
        limit = tag_amount(db, on_device ? 0xDF8125 : 0xDF8124, -1);
    if (limit >= 0 && amount > limit) {
        opk_k_select_next(out, OPK_L2_MAX_LIMIT_EXCEEDED, 0);
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

    /* 8. GENERATE AC (with CDA when selected) */
    int cid = opk_k_generate_ac(s, ac, cda);
    if (cid == OPK_ERR_TRANSMIT)
        return cid;
    if (cid == OPK_K_STATUS_WORD) {
        opk_outcome_end(out, OPK_L2_STATUS_BYTES, s->sw, OPK_MSG_PROCESSING_ERROR);
        return OPK_OK;
    }
    if (cid == OPK_K_CDA_FAILED) {
        opk_k_final(s, out, OPK_STATUS_DECLINED, cvm, OPK_L2_CAM_FAILED);
        return OPK_OK;
    }
    if (cid < 0)
        goto card_error;
    opk_k_final(s, out, opk_k_status_for(cid), cvm, OPK_L2_OK);
    return OPK_OK;

card_error:
    opk_outcome_end(out, OPK_L2_CARD_DATA_ERROR, 0, OPK_MSG_PROCESSING_ERROR);
    return OPK_OK;
}
