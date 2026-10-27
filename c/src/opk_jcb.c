/* Kernel 5: JCB J/Speedy (EMV Contactless Book C-5), EMV mode.
 * Mirrors python/openpaykernel/kernels/jcb.py.
 *
 * Terminal Interchange Profile (9F53) in the PDOL -> GPO -> READ RECORD -> CDA selection ->
 * processing restrictions -> CVM (on-device CVM or CVM List with the TIP's capabilities) ->
 * floor limit -> TAA -> GENERATE AC (CDA). TIP byte 1: (1,8) CVM required (per transaction),
 * (1,7) signature, (1,6) online PIN, (1,5) on-device CVM, (1,2) contact chip supported.
 * Not verified against the official Book C-5 text. Legacy (mag-stripe) mode is not implemented.
 * SPDX-License-Identifier: Apache-2.0 */
#include "opk_internal.h"

int opk_kernel_jcb(const opk_kernel_ctx *k, opk_outcome *out)
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

    /* Terminal Interchange Profile: configuration value + the CVM-required bit */
    uint8_t tip[3] = {0x72, 0x00, 0x00};
    opk_tlv cfg_tip;
    if (cfg->extra_len && opk_tlv_find(cfg->extra, cfg->extra_len, 0x9F53, &cfg_tip) == 1) {
        memset(tip, 0, 3);
        memcpy(tip, cfg_tip.val, cfg_tip.len < 3 ? cfg_tip.len : 3);
    }
    tip[0] &= 0x7F;
    if (cfg->cvm_required_limit >= 0 && k->txn->amount >= cfg->cvm_required_limit)
        tip[0] |= 0x80;
    opk_db_set(db, 0x9F53, tip, 3);

    if (opk_build_dol_tag(s, 0x9F38, (const uint8_t *)"", 0, s->pdol_data, sizeof s->pdol_data, &s->pdol_len))
        goto card_error;
    if (opk_gpo(s))
        return OPK_ERR_TRANSMIT;
    if (s->sw == 0x6984) {
        opk_k_try_another_interface(out);
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
    if (!BIT(aip, 2, 8) || !opk_db_get(db, 0x94, &l) || !l) {
        opk_outcome_end(out, OPK_L2_MAGSTRIPE_NOT_SUPPORTED, 0, OPK_MSG_INSERT_SWIPE_OR_TRY_ANOTHER);
        return OPK_OK;
    }

    r = opk_read_application_data(s);
    if (r == OPK_ERR_TRANSMIT)
        return r;
    static const uint32_t mand[] = {0x5F24, 0x5A, 0x8C};
    if (r || opk_check_mandatory(s, mand, 3))
        goto card_error;
    int cda = opk_k_select_cda(s, aip, BIT(k->env->terminal.capabilities, 3, 4));
    if (opk_processing_restrictions(s))
        goto card_error;

    int cvm_required = BIT(tip, 1, 8);
    opk_cvm cvm;
    if (cvm_required && BIT(aip, 1, 2) && BIT(tip, 1, 5)) {
        opk_db_set(db, 0x9F34, (const uint8_t *)"\x01\x00\x02", 3);
        cvm = OPK_CVM_CONFIRMATION_CODE_VERIFIED;
    } else {
        uint8_t caps[3];
        memcpy(caps, k->env->terminal.capabilities, 3);
        /* below the CVM limit only "No CVM required" is offered; above it, what the TIP allows */
        caps[1] = cvm_required ? (uint8_t)((BIT(tip, 1, 6) ? 0x40 : 0) | (BIT(tip, 1, 7) ? 0x20 : 0)) : 0x08;
        opk_cvm_result res;
        opk_cvm_list_processing(s, caps, opk_k_no_pin, NULL, &res);
        opk_db_set(db, 0x9F34, res.results, 3);
        cvm = res.online_pin ? OPK_CVM_ONLINE_PIN : res.signature ? OPK_CVM_SIGNATURE : OPK_CVM_NO_CVM;
    }

    if (k->txn->amount > cfg->floor_limit)
        TVR(s, 4, 8);
    int online_capable = opk_online_capable(&k->env->terminal);
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
