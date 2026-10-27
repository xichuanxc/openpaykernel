/* Steps shared by the contactless kernels that finish with GENERATE AC (kernels 2, 4, 5, 6).
 * Mirrors python/openpaykernel/kernels/common.py.
 * SPDX-License-Identifier: Apache-2.0 */
#include "opk_internal.h"

int opk_k_store_fci(opk_session *s, const opk_kernel_ctx *k)
{
    size_t pos = 0;
    opk_tlv top;
    if (opk_tlv_check(k->fci, k->fci_len))
        return OPK_ERR_TLV;
    if (opk_tlv_next(k->fci, k->fci_len, &pos, &top) != 1 || top.tag != 0x6F)
        return 0;
    opk_tlv_store_card(s->db, k->fci, k->fci_len);
    opk_db_set(s->db, 0x9F06, k->adf_name, k->adf_len);
    return 1;
}

int opk_k_select_cda(opk_session *s, const uint8_t aip[2], int terminal_supports_cda)
{
    if (!(BIT(aip, 1, 1) && terminal_supports_cda)) {
        TVR(s, 1, 8); /* ODA not performed */
        opk_session_sync(s);
        return 0;
    }
    size_t il, l;
    const uint8_t *idx = opk_db_get(s->db, 0x8F, &il);
    const uint8_t *adf = opk_db_get(s->db, 0x9F06, &l);
    if (!idx || il < 1 || !adf || l < 5 || !opk_find_capk(s->env, adf, idx[0], s->txn->date))
        TVR(s, 1, 3); /* CDA failed: no CA public key */
    opk_session_sync(s);
    return 1;
}

int opk_k_generate_ac(opk_session *s, int ac, int cda)
{
    opk_db *db = s->db;
    size_t l;
    int request_cda = cda && !BIT(s->tvr, 1, 3) && ac != AC_AAC;
    if (opk_build_dol_tag(s, 0x8C, (const uint8_t *)"", 0, s->cdol1_data, sizeof s->cdol1_data, &s->cdol1_len))
        return OPK_ERR_CARD;
    uint8_t cmd[270];
    size_t cl = opk_cmd(cmd, 0x80, 0xAE, (uint8_t)(ac | (request_cda ? AC_CDA : 0)), 0x00, s->cdol1_data,
                        s->cdol1_len, 0);
    if (opk_exchange(s, cmd, cl))
        return OPK_ERR_TRANSMIT;
    if (s->sw != 0x9000)
        return OPK_K_STATUS_WORD;
    const uint8_t *children;
    size_t children_len;
    if (opk_parse_generate_ac(s, &children, &children_len))
        return OPK_ERR_CARD;
    uint8_t cid_byte = opk_db_get(db, 0x9F27, &l)[0];
    int cid = cid_byte & 0xC0;
    if (request_cda && cid != AC_AAC) {
        size_t sl;
        const uint8_t *sdad = opk_db_get(db, 0x9F4B, &sl);
        opk_pubkey icc;
        if (!sdad || opk_retrieve_icc_pk(s, &icc)) {
            TVR(s, 1, 3);
            opk_session_sync(s);
            return OPK_K_CDA_FAILED;
        }
        /* PDOL data || CDOL1 data || response TLVs other than 9F4B */
        uint8_t tx[1024];
        size_t tl = 0, p = 0;
        memcpy(tx, s->pdol_data, s->pdol_len);
        tl += s->pdol_len;
        memcpy(tx + tl, s->cdol1_data, s->cdol1_len);
        tl += s->cdol1_len;
        opk_tlv c;
        while (opk_tlv_next(children, children_len, &p, &c) == 1)
            if (c.tag != 0x9F4B && tl + c.raw_len <= sizeof tx) {
                memcpy(tx + tl, c.raw, c.raw_len);
                tl += c.raw_len;
            }
        uint8_t acv[8], un[8], sdad_copy[OPK_MAX_RSA_BYTES];
        size_t ul;
        memcpy(un, opk_db_get(db, 0x9F37, &ul), 4);
        memcpy(sdad_copy, sdad, sl);
        if (opk_oda_verify_cda(&icc, sdad_copy, sl, un, ul, cid_byte, tx, tl, acv)) {
            TVR(s, 1, 3);
            opk_session_sync(s);
            return OPK_K_CDA_FAILED;
        }
        opk_db_set(db, 0x9F26, acv, 8);
    } else if (!opk_db_has(db, 0x9F26)) {
        return OPK_ERR_CARD;
    }
    return cid;
}

/* Contactless kernels never verify a PIN with the card: online PIN / signature are recorded only. */
int opk_k_no_pin(opk_session *s, uint8_t method, void *ctx)
{
    (void)s; (void)method; (void)ctx;
    return OPK_RESULT_UNKNOWN;
}

opk_status opk_k_status_for(int cid)
{
    return cid == AC_TC ? OPK_STATUS_APPROVED : cid == AC_ARQC ? OPK_STATUS_ONLINE_REQUEST : OPK_STATUS_DECLINED;
}

void opk_k_final(opk_session *s, opk_outcome *o, opk_status st, opk_cvm cvm, opk_l2_error l2)
{
    opk_session_sync(s);
    opk_message m = st == OPK_STATUS_APPROVED ? (cvm == OPK_CVM_SIGNATURE ? OPK_MSG_APPROVED_SIGN : OPK_MSG_APPROVED)
                    : st == OPK_STATUS_DECLINED ? OPK_MSG_NOT_AUTHORISED : OPK_MSG_AUTHORISING;
    opk_outcome_set(o, st, cvm, m);
    o->l2_error = l2;
}

void opk_k_select_next(opk_outcome *o, opk_l2_error l2, uint16_t sw)
{
    opk_outcome_set(o, OPK_STATUS_SELECT_NEXT, OPK_CVM_NA, OPK_MSG_NA);
    o->start = 2;
    o->l2_error = l2;
    o->sw12 = sw;
}

void opk_k_try_another_interface(opk_outcome *o)
{
    opk_outcome_set(o, OPK_STATUS_TRY_ANOTHER_INTERFACE, OPK_CVM_NA, OPK_MSG_INSERT_CARD);
    o->alt_interface_contact = 1;
}
