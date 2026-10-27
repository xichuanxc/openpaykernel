/* Kernel 6: Discover D-PAS (EMV Contactless Book C-6), EMV mode.
 * Mirrors python/openpaykernel/kernels/discover.py.
 *
 * TTQ in the PDOL -> GPO (AIP, AFL, Card Processing Requirements 9F71) -> READ RECORD ->
 * interface-switch rules -> CDA selection -> processing restrictions -> CVM from TTQ + CPR ->
 * floor limit -> TAA -> GENERATE AC (CDA) -> outcome.
 * CPR bits used: (1,8) online PIN required, (1,7) signature required, (1,3) switch interface
 * for cash, (1,2) switch interface for cashback, (2,8) consumer device CVM performed.
 * Not verified against the official Book C-6 text. Mag-stripe mode is not implemented.
 * SPDX-License-Identifier: Apache-2.0 */
#include "opk_internal.h"

/* -1 = no CVM can be performed */
static int cvm_from_cpr(const uint8_t ttq[4], const uint8_t *cpr, size_t cl)
{
    int has = cpr && cl >= 1;
    uint8_t c1 = has ? cpr[0] : 0, c2 = (has && cl >= 2) ? cpr[1] : 0;
    if (!BIT(ttq, 2, 7))
        return OPK_CVM_NO_CVM;
    if (has) {
        if ((c1 & 0x80) && BIT(ttq, 1, 3))
            return OPK_CVM_ONLINE_PIN;
        if (c2 & 0x80)
            return OPK_CVM_CONFIRMATION_CODE_VERIFIED;
        if ((c1 & 0x40) && BIT(ttq, 1, 2))
            return OPK_CVM_SIGNATURE;
        return -1;
    }
    if (BIT(ttq, 1, 2))
        return OPK_CVM_SIGNATURE;
    if (BIT(ttq, 1, 3))
        return OPK_CVM_ONLINE_PIN;
    return -1;
}

int opk_kernel_discover(const opk_kernel_ctx *k, opk_outcome *out)
{
    opk_session sess;
    opk_session *s = &sess;
    opk_db *db = k->db;
    const opk_aid_config *cfg = k->aid;
    size_t l;
    opk_session_init(s, k->env, cfg, k->txn, k->reader, db);

    int r = opk_k_store_fci(s, k);
    if (r < 0) {
        opk_outcome_end(out, OPK_L2_PARSING_ERROR, 0, OPK_MSG_PROCESSING_ERROR);
        return OPK_OK;
    }
    if (r == 0) {
        opk_k_select_next(out, OPK_L2_PARSING_ERROR, 0);
        return OPK_OK;
    }
    uint8_t ttq[4];
    memcpy(ttq, k->has_ttq ? k->ttq : cfg->ttq, 4);
    opk_db_set(db, 0x9F66, ttq, 4);

    if (opk_build_dol_tag(s, 0x9F38, (const uint8_t *)"", 0, s->pdol_data, sizeof s->pdol_data, &s->pdol_len))
        goto card_error;
    if (opk_gpo(s))
        return OPK_ERR_TRANSMIT;
    if (s->sw == 0x6984) {
        opk_k_try_another_interface(out);
        return OPK_OK;
    }
    if (s->sw == 0x6986) {
        opk_outcome_set(out, OPK_STATUS_TRY_AGAIN, OPK_CVM_NA, OPK_MSG_SEE_PHONE);
        out->start = 1;
        out->field_off_ms = 1300;
        return OPK_OK;
    }
    if (s->sw != 0x9000) {
        opk_k_select_next(out, OPK_L2_STATUS_BYTES, s->sw);
        return OPK_OK;
    }
    if (opk_tlv_check(s->rsp, s->rsp_len)) {
        opk_outcome_end(out, OPK_L2_PARSING_ERROR, 0, OPK_MSG_PROCESSING_ERROR);
        return OPK_OK;
    }
    if (opk_parse_gpo(s))
        goto card_error;
    uint8_t aip[2] = {0, 0};
    const uint8_t *v = opk_db_get(db, 0x82, &l);
    memcpy(aip, v, l < 2 ? l : 2);
    size_t cprl;
    const uint8_t *cpr_p = opk_db_get(db, 0x9F71, &cprl);
    uint8_t cpr[2] = {0, 0};
    if (cpr_p)
        memcpy(cpr, cpr_p, cprl < 2 ? cprl : 2);
    if (!opk_db_get(db, 0x94, &l) || !l) {
        opk_outcome_end(out, OPK_L2_MAGSTRIPE_NOT_SUPPORTED, 0, OPK_MSG_INSERT_SWIPE_OR_TRY_ANOTHER);
        return OPK_OK;
    }

    r = opk_read_application_data(s);
    if (r == OPK_ERR_TRANSMIT)
        return r;
    static const uint32_t mand[] = {0x5F24, 0x5A, 0x8C};
    if (r || opk_check_mandatory(s, mand, 3))
        goto card_error;

    int is_cash = k->txn->type == 0x01 || k->txn->type == 0x17;
    int is_cashback = k->txn->type == 0x09 || k->txn->amount_other > 0;
    if (cpr_p && cprl && ((is_cash && BIT(cpr, 1, 3)) || (is_cashback && BIT(cpr, 1, 2)))) {
        opk_k_try_another_interface(out);
        return OPK_OK;
    }

    int cda = opk_k_select_cda(s, aip, BIT(k->env->terminal.capabilities, 3, 4));
    if (opk_processing_restrictions(s))
        goto card_error;

    int cvm = cvm_from_cpr(ttq, cpr_p ? cpr : NULL, cpr_p ? cprl : 0);
    if (cvm < 0) {
        opk_db_set(db, 0x9F34, (const uint8_t *)"\x3F\x00\x01", 3);
        opk_k_final(s, out, OPK_STATUS_DECLINED, OPK_CVM_NO_CVM, OPK_L2_OK);
        return OPK_OK;
    }
    static const uint8_t results[4][3] = {{0x3F, 0x00, 0x00}, {0x1E, 0x03, 0x00}, {0x42, 0x03, 0x00},
                                          {0x01, 0x00, 0x02}};
    opk_db_set(db, 0x9F34, results[cvm], 3); /* indexed by opk_cvm 0..3 */

    if (k->txn->amount > cfg->floor_limit)
        TVR(s, 4, 8);
    int online_capable = opk_online_capable(&k->env->terminal) && !BIT(ttq, 1, 4);
    int ac = opk_terminal_action_analysis(s, cfg->tac_denial, cfg->tac_online, cfg->tac_default, online_capable);
    if (cvm == OPK_CVM_ONLINE_PIN && ac == AC_TC)
        ac = online_capable ? AC_ARQC : AC_AAC; /* online PIN cannot be approved offline */

    int cid = opk_k_generate_ac(s, ac, cda);
    if (cid == OPK_ERR_TRANSMIT)
        return cid;
    if (cid == OPK_K_STATUS_WORD) {
        opk_outcome_end(out, OPK_L2_STATUS_BYTES, s->sw, OPK_MSG_PROCESSING_ERROR);
        return OPK_OK;
    }
    if (cid == OPK_K_CDA_FAILED) {
        opk_k_final(s, out, OPK_STATUS_DECLINED, (opk_cvm)cvm, OPK_L2_CAM_FAILED);
        return OPK_OK;
    }
    if (cid < 0)
        goto card_error;
    opk_k_final(s, out, opk_k_status_for(cid), (opk_cvm)cvm, OPK_L2_OK);
    return OPK_OK;

card_error:
    opk_outcome_end(out, OPK_L2_CARD_DATA_ERROR, 0, OPK_MSG_PROCESSING_ERROR);
    return OPK_OK;
}
