/* dump_baseline.c - prints the three frames of the reference scenario exactly as the C code builds them (sim_build_frame, the
 * measured scene: three robotaxis and a human-driven car), as Rust byte arrays, and the plan hash the real C code computes for them.
 * Build/run: see rust_port/run_planner_diff.sh (target "dump"). Output is pasted into rust_port/src/lib.rs (BASELINE_FRAMES). */
#include <unistd.h>
#define main v2v_orig_main
#include "../../qnx_target/src/v2v_ttl_resmgr.c"
#undef main

int main(void) {
    g_quiet = 1;
    v2v_ephemeral_frame_t fr[3];
    memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
    uint64_t now = now_monotonic_us();
    for (int v = 0; v < 3; ++v) {
        sim_build_frame(v, 0, &fr[v], NULL);          /* now_us = 0: only t_ms depends on the clock, and the plan does not use it */
        if (v2v_cache_upsert(&fr[v], now) != 0) { fprintf(stderr, "ERROR frame %d not accepted\n", v); return 1; }
    }
    v2v_arbitration_report_t r;
    memset(&r, 0, sizeof r);
    v2v_run_handshake_arbitration(&r);
    printf("// C plan hash for these frames: 0x%08X\n", r.sequence_hash);
    printf("pub const BASELINE_FRAMES: [[u8; 56]; 3] = [\n");
    for (int v = 0; v < 3; ++v) {
        const uint8_t *b = (const uint8_t *)&fr[v];
        printf("    [");
        for (size_t i = 0; i < sizeof fr[v]; ++i) printf("%s%u", i ? ", " : "", b[i]);
        printf("],\n");
    }
    printf("];\n");
    printf("// summary: %s\n", r.resolution_summary);
    return r.sequence_hash == 0x4F390A9AU ? 0 : 2;
}
