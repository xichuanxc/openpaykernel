/* Contactless Entry Point (EMV Contactless Book B).
 * SPDX-License-Identifier: Apache-2.0 */
#include "opk_internal.h"

typedef struct {
    int not_allowed, status_check, zero_amount, cvm_limit_exceeded, floor_exceeded, cl_limit_exceeded;
    uint32_t kernel_id;
    uint8_t ttq[4];
    int has_ttq;
    int enabled;
} combo;

typedef struct {
    uint8_t adf[16];
    uint8_t adf_len;
    uint32_t kernel_id;
    uint8_t priority;
    int combo;
    int order;
} candidate;

static uint32_t default_kernel(const uint8_t *aid)
{
    static const struct { const char *rid; uint32_t k; } map[] = {
        {"\xA0\x00\x00\x00\x04", 2}, {"\xA0\x00\x00\x00\x03", 3}, {"\xA0\x00\x00\x00\x25", 4},
        {"\xA0\x00\x00\x00\x65", 5}, {"\xA0\x00\x00\x01\x52", 6}, {"\xA0\x00\x00\x03\x33", 7},
    };
    for (size_t i = 0; i < sizeof map / sizeof map[0]; i++)
        if (!memcmp(aid, map[i].rid, 5))
            return map[i].k;
    return 0;
}

static uint32_t requested_kernel(const uint8_t *kid, size_t kl, const uint8_t *aid)
{
    if (!kid || !kl || kid[0] == 0)
        return default_kernel(aid);
    if ((kid[0] >> 6) <= 1)
        return kid[0] & 0x3F;
    uint32_t v = 0;
    for (size_t i = 0; i < kl && i < 3; i++)
        v = v << 8 | kid[i];
    return v;
}

typedef int (*kernel_fn)(const opk_kernel_ctx *k, opk_outcome *out);

/* Kernel registry: ID -> implementation. Kernel 7 (UnionPay qUICS) reuses the qVSDC engine. */
static kernel_fn kernel_for(uint32_t k)
{
    switch (k) {
    case OPK_KERNEL_MASTERCARD: return opk_kernel_mastercard;
    case OPK_KERNEL_VISA: return opk_kernel_visa;
    case OPK_KERNEL_UNIONPAY: return opk_kernel_visa;
    case OPK_KERNEL_DISCOVER: return opk_kernel_discover;
    case OPK_KERNEL_AMEX: return opk_kernel_amex;
    case OPK_KERNEL_JCB: return opk_kernel_jcb;
    default: return NULL;
    }
}

static int kernel_supported(uint32_t k) { return kernel_for(k) != NULL; }

/* Kernels whose PDOL carries the Terminal Transaction Qualifiers built at pre-processing */
static int uses_ttq(uint32_t k) { return k == OPK_KERNEL_VISA || k == OPK_KERNEL_DISCOVER || k == OPK_KERNEL_UNIONPAY; }

static void try_again(opk_outcome *out)
{
    opk_outcome_set(out, OPK_STATUS_TRY_AGAIN, OPK_CVM_NA, OPK_MSG_PRESENT_CARD_AGAIN);
    out->start = 1;
    out->l1_error = 2;
}

int opk_contactless_process(const opk_env *env, const opk_transaction *txn, const opk_reader *reader,
                            opk_outcome *out, opk_db *db)
{
    combo combos[OPK_MAX_AIDS];
    candidate cands[OPK_MAX_CANDIDATES];
    int ncand = 0, any = 0;
    opk_db_init(db);

    /* --- Start A: pre-processing (Book B 3.1) */
    uint32_t one_unit = 1;
    for (int i = 0; i < txn->currency_exponent; i++)
        one_unit *= 10;
    for (int i = 0; i < env->aid_count; i++) {
        const opk_aid_config *cfg = &env->aids[i];
        combo *c = &combos[i];
        memset(c, 0, sizeof *c);
        c->kernel_id = cfg->kernel_id ? cfg->kernel_id : default_kernel(cfg->aid);
        if (!kernel_supported(c->kernel_id))
            continue;
        c->enabled = 1;
        uint32_t amount = txn->amount;
        if (cfg->status_check && amount == one_unit)
            c->status_check = 1;
        if (amount == 0) {
            if (cfg->zero_amount_allowed) c->zero_amount = 1;
            else c->not_allowed = 1;
        }
        if (cfg->cl_transaction_limit >= 0 && amount >= cfg->cl_transaction_limit) {
            c->cl_limit_exceeded = 1;
            if (cfg->cl_transaction_limit_cdcvm < 0)
                c->not_allowed = 1;
        }
        if (amount > cfg->floor_limit)
            c->floor_exceeded = 1;
        if (cfg->cvm_required_limit >= 0 && amount >= cfg->cvm_required_limit)
            c->cvm_limit_exceeded = 1;
        if (uses_ttq(c->kernel_id)) {
            memcpy(c->ttq, cfg->ttq, 4);
            c->ttq[1] &= 0x3F;
            if (c->status_check || c->zero_amount || c->floor_exceeded)
                c->ttq[1] |= 0x80;
            if (c->cvm_limit_exceeded)
                c->ttq[1] |= 0x40;
            c->has_ttq = 1;
        }
        if (!c->not_allowed)
            any = 1;
    }
    if (!any) {
        opk_outcome_set(out, OPK_STATUS_TRY_ANOTHER_INTERFACE, OPK_CVM_NA, OPK_MSG_INSERT_CARD);
        out->alt_interface_contact = 1;
        return OPK_OK;
    }

    /* --- Start C: combination selection (Book B 3.3) */
    uint8_t cmd[64], rsp[300];
    size_t rl = sizeof rsp;
    uint16_t sw;
    size_t cl = opk_cmd_select(cmd, (const uint8_t *)"2PAY.SYS.DDF01", 14, 1);
    if (opk_xchg(reader, cmd, cl, rsp, &rl, &sw)) {
        try_again(out);
        return OPK_OK;
    }
    if (sw != 0x9000) {
        opk_outcome_end(out, OPK_L2_NO_PPSE, sw, OPK_MSG_INSERT_SWIPE_OR_TRY_ANOTHER);
        return OPK_OK;
    }
    opk_tlv top, bf0c;
    size_t pos = 0;
    if (opk_tlv_check(rsp, rl) || opk_tlv_next(rsp, rl, &pos, &top) != 1 || top.tag != 0x6F ||
        opk_tlv_find(top.val, top.len, 0xBF0C, &bf0c) != 1) {
        opk_outcome_end(out, OPK_L2_PPSE_FAULT, sw, OPK_MSG_INSERT_SWIPE_OR_TRY_ANOTHER);
        return OPK_OK;
    }
    pos = 0;
    opk_tlv e;
    int order = 0;
    while (opk_tlv_next(bf0c.val, bf0c.len, &pos, &e) == 1 && ncand < OPK_MAX_CANDIDATES) {
        opk_tlv adf, kid, prio;
        if (e.tag != 0x61 || opk_tlv_find(e.val, e.len, 0x4F, &adf) != 1 || adf.len < 5 || adf.len > 16)
            continue;
        int has_kid = opk_tlv_find(e.val, e.len, 0x9F2A, &kid) == 1;
        uint32_t k = requested_kernel(has_kid ? kid.val : NULL, has_kid ? kid.len : 0, adf.val);
        int has_prio = opk_tlv_find(e.val, e.len, 0x87, &prio) == 1 && prio.len;
        for (int i = 0; i < env->aid_count; i++) {
            const opk_aid_config *cfg = &env->aids[i];
            if (!combos[i].enabled || combos[i].not_allowed || combos[i].kernel_id != k)
                continue;
            int match = (adf.len == cfg->aid_len && !memcmp(adf.val, cfg->aid, adf.len)) ||
                        (cfg->partial_match && adf.len >= cfg->aid_len && !memcmp(adf.val, cfg->aid, cfg->aid_len));
            if (!match)
                continue;
            candidate *c = &cands[ncand++];
            memcpy(c->adf, adf.val, adf.len);
            c->adf_len = (uint8_t)adf.len;
            c->kernel_id = k;
            c->priority = has_prio ? (prio.val[0] & 0x0F) : 0;
            c->combo = i;
            c->order = order++;
            break;
        }
    }
    /* stable sort: priority 0 (none) last */
    for (int i = 1; i < ncand; i++) {
        candidate t = cands[i];
        int j = i - 1;
        while (j >= 0) {
            int a0 = cands[j].priority == 0, b0 = t.priority == 0;
            int greater = a0 != b0 ? a0 > b0 : cands[j].priority != t.priority ? cands[j].priority > t.priority
                                                                                 : cands[j].order > t.order;
            if (!greater)
                break;
            cands[j + 1] = cands[j];
            j--;
        }
        cands[j + 1] = t;
    }
    if (!ncand) {
        opk_outcome_end(out, OPK_L2_EMPTY_CANDIDATE_LIST, 0, OPK_MSG_INSERT_SWIPE_OR_TRY_ANOTHER);
        return OPK_OK;
    }

    /* --- final selection + kernel activation */
    uint8_t fci[300];
    for (int i = 0; i < ncand; i++) {
        candidate *c = &cands[i];
        size_t fl = sizeof fci;
        cl = opk_cmd_select(cmd, c->adf, c->adf_len, 1);
        if (opk_xchg(reader, cmd, cl, fci, &fl, &sw)) {
            try_again(out);
            out->ui_message = OPK_MSG_NA;
            return OPK_OK;
        }
        if (sw != 0x9000)
            continue;
        opk_kernel_ctx k = {env, txn, reader, &env->aids[c->combo], c->adf, c->adf_len, fci, fl, {0}, 0, db};
        if (combos[c->combo].has_ttq) {
            memcpy(k.ttq, combos[c->combo].ttq, 4);
            k.has_ttq = 1;
        }
        int r = kernel_for(c->kernel_id)(&k, out);
        if (r == OPK_ERR_TRANSMIT) {
            try_again(out);
            return OPK_OK;
        }
        if (out->status == OPK_STATUS_SELECT_NEXT)
            continue;
        return OPK_OK;
    }
    opk_outcome_end(out, OPK_L2_EMPTY_CANDIDATE_LIST, 0, OPK_MSG_INSERT_SWIPE_OR_TRY_ANOTHER);
    return OPK_OK;
}
