/* BER-TLV, the TLV database and Data Object Lists (EMV Book 3 Annex B, section 5.4).
 * SPDX-License-Identifier: Apache-2.0 */
#include "opk_internal.h"

/* ------------------------------------------------------------------ TLV */
static int first_byte(uint32_t tag)
{
    while (tag > 0xFF)
        tag >>= 8;
    return (int)tag;
}

int opk_tlv_constructed(uint32_t tag) { return (first_byte(tag) & 0x20) != 0; }

int opk_tlv_parse_tag(const uint8_t *buf, size_t len, size_t *pos, uint32_t *tag)
{
    size_t p = *pos;
    if (p >= len)
        return OPK_ERR_TLV;
    uint32_t t = buf[p++];
    if ((t & 0x1F) == 0x1F) {
        int n = 0;
        do {
            if (p >= len || ++n > 3)
                return OPK_ERR_TLV;
            t = (t << 8) | buf[p];
        } while (buf[p++] & 0x80);
    }
    *tag = t;
    *pos = p;
    return OPK_OK;
}

int opk_tlv_parse_len(const uint8_t *buf, size_t len, size_t *pos, size_t *out)
{
    size_t p = *pos;
    if (p >= len)
        return OPK_ERR_TLV;
    uint8_t b = buf[p++];
    if (b < 0x80) {
        *out = b;
    } else {
        int n = b & 0x7F;
        if (n == 0 || n > 3 || p + (size_t)n > len)
            return OPK_ERR_TLV;
        size_t v = 0;
        while (n--)
            v = (v << 8) | buf[p++];
        *out = v;
    }
    *pos = p;
    return OPK_OK;
}

int opk_tlv_next(const uint8_t *buf, size_t len, size_t *pos, opk_tlv *out)
{
    while (*pos < len && (buf[*pos] == 0x00 || buf[*pos] == 0xFF))
        (*pos)++;
    if (*pos >= len)
        return 0;
    size_t start = *pos, l;
    uint32_t tag;
    if (opk_tlv_parse_tag(buf, len, pos, &tag) || opk_tlv_parse_len(buf, len, pos, &l) || *pos + l > len)
        return OPK_ERR_TLV;
    out->tag = tag;
    out->val = buf + *pos;
    out->len = l;
    out->raw = buf + start;
    *pos += l;
    out->raw_len = *pos - start;
    return 1;
}

int opk_tlv_find(const uint8_t *buf, size_t len, uint32_t tag, opk_tlv *out)
{
    size_t pos = 0;
    opk_tlv t;
    int r;
    while ((r = opk_tlv_next(buf, len, &pos, &t)) == 1) {
        if (t.tag == tag) {
            *out = t;
            return 1;
        }
        if (opk_tlv_constructed(t.tag) && opk_tlv_find(t.val, t.len, tag, out) == 1)
            return 1;
    }
    return 0;
}

int opk_tlv_check(const uint8_t *buf, size_t len)
{
    size_t pos = 0;
    opk_tlv t;
    int r;
    while ((r = opk_tlv_next(buf, len, &pos, &t)) == 1)
        if (opk_tlv_constructed(t.tag) && opk_tlv_check(t.val, t.len))
            return OPK_ERR_TLV;
    return r < 0 ? OPK_ERR_TLV : OPK_OK;
}

int opk_tlv_store_all(opk_db *db, const uint8_t *buf, size_t len)
{
    size_t pos = 0;
    opk_tlv t;
    int r;
    while ((r = opk_tlv_next(buf, len, &pos, &t)) == 1) {
        if (opk_tlv_constructed(t.tag)) {
            if ((r = opk_tlv_store_all(db, t.val, t.len)) != OPK_OK)
                return r;
        } else if (opk_db_set(db, t.tag, t.val, t.len) != OPK_OK) {
            return OPK_ERR_FULL;
        }
    }
    return r < 0 ? OPK_ERR_TLV : OPK_OK;
}

int opk_tlv_store_card(opk_db *db, const uint8_t *buf, size_t len)
{
    size_t pos = 0;
    opk_tlv t;
    int r;
    while ((r = opk_tlv_next(buf, len, &pos, &t)) == 1) {
        if (opk_tlv_constructed(t.tag)) {
            if ((r = opk_tlv_store_card(db, t.val, t.len)) != OPK_OK)
                return r;
        } else if (!opk_tag_is_terminal(t.tag) && opk_db_set(db, t.tag, t.val, t.len) != OPK_OK) {
            return OPK_ERR_FULL;
        }
    }
    return r < 0 ? OPK_ERR_TLV : OPK_OK;
}

size_t opk_tlv_encode(uint32_t tag, const uint8_t *val, size_t len, uint8_t *out)
{
    size_t n = 0;
    if (tag > 0xFFFFFF) out[n++] = (uint8_t)(tag >> 24);
    if (tag > 0xFFFF) out[n++] = (uint8_t)(tag >> 16);
    if (tag > 0xFF) out[n++] = (uint8_t)(tag >> 8);
    out[n++] = (uint8_t)tag;
    if (len < 0x80) {
        out[n++] = (uint8_t)len;
    } else if (len <= 0xFF) {
        out[n++] = 0x81;
        out[n++] = (uint8_t)len;
    } else {
        out[n++] = 0x82;
        out[n++] = (uint8_t)(len >> 8);
        out[n++] = (uint8_t)len;
    }
    if (len)
        memmove(out + n, val, len);
    return n + len;
}

/* ------------------------------------------------------------------ database */
void opk_db_init(opk_db *db)
{
    db->count = 0;
    db->used = 0;
}

static opk_db_entry *db_find(const opk_db *db, uint32_t tag)
{
    for (int i = 0; i < db->count; i++)
        if (db->e[i].tag == tag)
            return (opk_db_entry *)&db->e[i];
    return NULL;
}

int opk_db_set(opk_db *db, uint32_t tag, const uint8_t *val, size_t len)
{
    opk_db_entry *e = db_find(db, tag);
    if (e && len <= e->len) {
        memmove(db->pool + e->off, val, len);
        e->len = (uint16_t)len;
        return OPK_OK;
    }
    if ((size_t)db->used + len > OPK_DB_POOL_SIZE)
        return OPK_ERR_FULL;
    if (!e) {
        if (db->count >= OPK_DB_MAX_ENTRIES)
            return OPK_ERR_FULL;
        e = &db->e[db->count++];
        e->tag = tag;
    }
    memmove(db->pool + db->used, val, len);
    e->off = db->used;
    e->len = (uint16_t)len;
    db->used = (uint16_t)(db->used + len);
    return OPK_OK;
}

const uint8_t *opk_db_get(const opk_db *db, uint32_t tag, size_t *len)
{
    const opk_db_entry *e = db_find(db, tag);
    if (!e)
        return NULL;
    if (len)
        *len = e->len;
    return db->pool + e->off;
}

int opk_db_has(const opk_db *db, uint32_t tag) { return db_find(db, tag) != NULL; }

void opk_db_del(opk_db *db, uint32_t tag)
{
    opk_db_entry *e = db_find(db, tag);
    if (e) {
        *e = db->e[db->count - 1];
        db->count--;
    }
}

/* ------------------------------------------------------------------ data dictionary */
static const struct {
    uint32_t tag;
    char fmt;
    char term;
} DICT[] = {
    {0x42, 'n', 0},     {0x5A, 'c', 0},     {0x5F24, 'n', 0},   {0x5F25, 'n', 0},   {0x5F28, 'n', 0},
    {0x5F2A, 'n', 1},   {0x5F30, 'n', 0},   {0x5F34, 'n', 0},   {0x5F36, 'n', 1},   {0x9A, 'n', 1},
    {0x9C, 'n', 1},     {0x9F01, 'n', 1},   {0x9F02, 'n', 1},   {0x9F03, 'n', 1},   {0x9F11, 'n', 0},
    {0x9F15, 'n', 1},   {0x9F1A, 'n', 1},   {0x9F20, 'c', 0},   {0x9F21, 'n', 1},   {0x9F35, 'n', 1},
    {0x9F39, 'n', 1},   {0x9F41, 'n', 1},   {0x9F42, 'n', 0},   {0x9F44, 'n', 0},   {0xDF8123, 'n', 1},
    {0xDF8124, 'n', 1}, {0xDF8125, 'n', 1}, {0xDF8126, 'n', 1}, {0x50, 'a', 0},     {0x5F20, 'a', 0},
    {0x5F2D, 'a', 0},   {0x9F12, 'a', 0},   {0x9F16, 'a', 1},   {0x9F1C, 'a', 1},   {0x9F1E, 'a', 1},
    {0x9F4E, 'a', 1},   {0x8A, 'a', 0},     {0x95, 'b', 1},     {0x9B, 'b', 1},     {0x9F06, 'b', 1},
    {0x9F09, 'b', 1},   {0x9F1B, 'b', 1},   {0x9F33, 'b', 1},   {0x9F34, 'b', 1},   {0x9F37, 'b', 1},
    {0x99, 'b', 1},     {0x9F6D, 'b', 1},   {0x9F7E, 'b', 1},   {0x9F40, 'b', 1},   {0x9F66, 'b', 1},   {0x98, 'b', 1},     {0x9F53, 'a', 1},   {0x9F1D, 'b', 1},
};

char opk_tag_format(uint32_t tag)
{
    for (size_t i = 0; i < sizeof DICT / sizeof DICT[0]; i++)
        if (DICT[i].tag == tag)
            return DICT[i].fmt;
    return 'b';
}

int opk_tag_is_terminal(uint32_t tag)
{
    if (tag >= 0xDF8100 && tag <= 0xDF81FF)
        return 1;
    for (size_t i = 0; i < sizeof DICT / sizeof DICT[0]; i++)
        if (DICT[i].tag == tag)
            return DICT[i].term;
    return 0;
}

/* ------------------------------------------------------------------ DOL */
int opk_dol_build(const uint8_t *dol, size_t dol_len, const opk_db *db, uint8_t *out, size_t cap, size_t *out_len)
{
    size_t pos = 0, n = 0;
    while (pos < dol_len) {
        uint32_t tag;
        size_t l;
        if (opk_tlv_parse_tag(dol, dol_len, &pos, &tag) || opk_tlv_parse_len(dol, dol_len, &pos, &l))
            return OPK_ERR_TLV;
        if (n + l > cap)
            return OPK_ERR_FULL;
        size_t vl = 0;
        const uint8_t *v = opk_tlv_constructed(tag) ? NULL : opk_db_get(db, tag, &vl);
        uint8_t *d = out + n;
        if (!v) {
            memset(d, 0, l);
        } else {
            char f = opk_tag_format(tag);
            if (vl == l) {
                memcpy(d, v, l);
            } else if (f == 'n') {          /* right-justify, leading zeros */
                if (vl > l) {
                    memcpy(d, v + (vl - l), l);
                } else {
                    memset(d, 0, l - vl);
                    memcpy(d + (l - vl), v, vl);
                }
            } else {                         /* left-justify, pad F (cn) or 00 */
                size_t c = vl < l ? vl : l;
                memcpy(d, v, c);
                memset(d + c, f == 'c' ? 0xFF : 0x00, l - c);
            }
        }
        n += l;
    }
    *out_len = n;
    return OPK_OK;
}

int opk_dol_contains(const uint8_t *dol, size_t dol_len, uint32_t want)
{
    size_t pos = 0;
    while (pos < dol_len) {
        uint32_t tag;
        size_t l;
        if (opk_tlv_parse_tag(dol, dol_len, &pos, &tag) || opk_tlv_parse_len(dol, dol_len, &pos, &l))
            return 0;
        if (tag == want)
            return 1;
    }
    return 0;
}
