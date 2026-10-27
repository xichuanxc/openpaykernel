/* Kernel 4: American Express ExpressPay (EMV Contactless Book C-4), EMV mode.
 * Mirrors python/openpaykernel/kernels/amex.py.
 *
 * Enhanced Contactless Reader Capabilities (9F6E) in the PDOL -> GPO -> READ RECORD -> CDA
 * selection -> processing restrictions -> CVM (mobile CVM or CVM List) -> floor limit -> TAA ->
 * GENERATE AC (CDA). 9F6E bits used: (2,8) mobile CVM, (2,7) online PIN, (2,6) signature,
 * (3,8) offline-only reader, (3,7) CVM required (set per transaction). Mobile CVM Results
 * (9F71) byte 3 = 02 means success. The reader capabilities stay in a local copy: 9F6E is card
 * data for other kernels. Not verified against the official Book C-4 text.
 * SPDX-License-Identifier: Apache-2.0 */
#include "opk_internal.h"

int opk_kernel_amex(const opk_kernel_ctx *k, opk_outcome *out)
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

    /* reader capabilities: configuration value (aid extra TLVs) + per-transaction bits */
    uint8_t ecrc[4] = {0xD8, 0xE0, 0x00, 0x03};
    opk_tlv cfg_ecrc;
    if (cfg->extra_len && opk_tlv_find(cfg->extra, cfg->extra_len, 0x9F6E, &cfg_ecrc) == 1) {
        memset(ecrc, 0, 4);
        memcpy(ecrc, cfg_ecrc.val, cfg_ecrc.len < 4 ? cfg_ecrc.len : 4);
    }
    ecrc[2] &= 0x3F;
    if ((k->env->terminal.terminal_type & 0x0F) == 3 || (k->env->terminal.terminal_type & 0x0F) == 6)
        ecrc[2] |= 0x80;
    if (cfg->cvm_required_limit >= 0 && k->txn->amount >= cfg->cvm_required_limit)
        ecrc[2] |= 0x40;
    opk_db_set(db, 0x9F6E, ecrc, 4);

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
    static const uint32_t mand[] = {0x5F24, 0x5A, 0x8C, 0x8D};
    if (r || opk_check_mandatory(s, mand, 4))
        goto card_error;
    int cda = opk_k_select_cda(s, aip, BIT(k->env->terminal.capabilities, 3, 4));
    if (opk_processing_restrictions(s))
        goto card_error;

    int cvm_required = BIT(ecrc, 3, 7);
    size_t ml;
    const uint8_t *mobile = opk_db_get(db, 0x9F71, &ml);
    opk_cvm cvm;
    if (mobile && ml == 3 && BIT(ecrc, 2, 8) && mobile[2] == 0x02) {
        uint8_t m[3];
        memcpy(m, mobile, 3);
        opk_db_set(db, 0x9F34, m, 3);
        cvm = OPK_CVM_CONFIRMATION_CODE_VERIFIED;
    } else {
        uint8_t caps[3];
        memcpy(caps, k->env->terminal.capabilities, 3);
        /* below the CVM limit only "No CVM required" is offered; above it, what the reader supports */
        caps[1] = cvm_required ? (uint8_t)((BIT(ecrc, 2, 7) ? 0x40 : 0) | (BIT(ecrc, 2, 6) ? 0x20 : 0)) : 0x08;
        opk_cvm_result res;
        opk_cvm_list_processing(s, caps, opk_k_no_pin, NULL, &res);
        opk_db_set(db, 0x9F34, res.results, 3);
        cvm = res.online_pin ? OPK_CVM_ONLINE_PIN : res.signature ? OPK_CVM_SIGNATURE : OPK_CVM_NO_CVM;
    }

    if (k->txn->amount > cfg->floor_limit)
        TVR(s, 4, 8);
    int online_capable = opk_online_capable(&k->env->terminal) && !BIT(ecrc, 3, 8);
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
