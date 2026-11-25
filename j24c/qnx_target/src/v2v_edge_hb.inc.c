/*
 * v2v_edge_hb.inc.c - G17 concern 3: the heartbeat v2 step digest, one definition for both sides (the vehicle program in v2v_ttl_resmgr.c
 * under V2V_G17, and v2v-edge). Needs iru_sha256 (v2v_iru.inc.c) and include/v2v_edge.h.
 *   digest = first 8 B of SHA-256(prev(8) counter(4) state(1) epoch(4) plan_hash(4) nonce(8) frames(8))
 * nonce  = the latest challenge the host received from the edge (all zero before the first one; always zero with negative control 0x800,
 *          where the edge sends markers without randomness)
 * frames = digest of every edge message the host had taken in when it read that challenge (all zero with negative control 0x400)
 * The edge computes the same value with the frame digest it kept itself for the messages it forwarded before the challenge.
 */
static void edge_hb_digest(const uint8_t prev[8], uint32_t counter, uint8_t state, uint32_t epoch, uint32_t plan, const uint8_t nonce[8],
                           const uint8_t frames[8], uint8_t out[8]) {
    uint8_t b[37], h[32];
    static const uint8_t zero[8] = {0};
    memcpy(b, prev, 8);
    memcpy(b + 8, &counter, 4);
    b[12] = state;
    memcpy(b + 13, &epoch, 4);
    memcpy(b + 17, &plan, 4);
    memcpy(b + 21, nonce, 8);
#if IRU_NEG(IRU_NEG_HB_COUNTER_ONLY)
    (void)frames;
    memcpy(b + 29, zero, 8);
#else
    (void)zero;
    memcpy(b + 29, frames, 8);
#endif
    if (iru_sha256(b, sizeof(b), h) != 0) memset(h, 0, sizeof(h));
    memcpy(out, h, 8);
}
/* rolling digest of the edge -> host messages (payload only): frames = first 8 B of SHA-256(frames || payload) */
static void edge_frames_fold(uint8_t frames[8], const uint8_t *payload, size_t n) {
    uint8_t b[8 + 300], h[32];
    if (n > 300) n = 300;
    memcpy(b, frames, 8);
    memcpy(b + 8, payload, n);
    if (iru_sha256(b, 8 + n, h) != 0) memset(h, 0, sizeof(h));
    memcpy(frames, h, 8);
}
/* link MAC: first 8 B of HMAC-SHA256(key, msg) */
#include <openssl/hmac.h>
static void edge_link_mac(const uint8_t key[32], const uint8_t *msg, size_t n, uint8_t out[8]) {
    uint8_t h[32];
    unsigned int hl = 0;
    if (HMAC(EVP_sha256(), key, 32, msg, n, h, &hl) == NULL || hl != 32) memset(h, 0xA5, sizeof(h));
    memcpy(out, h, 8);
}
static uint32_t edge_le32(const uint8_t *b) { return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24); }
/* parses one link message from r: 1 = whole message in m/len (header+payload+mac), 0 = need more, -1 = garbage (buffer dropped) */
static int edge_link_take(iru_rbuf_t *r, uint8_t *m, size_t *len) {
    if (r->n < EDGE_LINK_HDR) return 0;
    size_t pl = (size_t)r->b[5] | ((size_t)r->b[6] << 8);
    if (pl > 300) { r->n = 0; return -1; }
    size_t tot = EDGE_LINK_HDR + pl + EDGE_LINK_MAC;
    if (r->n < tot) return 0;
    memcpy(m, r->b, tot);
    memmove(r->b, r->b + tot, r->n - tot);
    r->n -= tot;
    *len = tot;
    return 1;
}
