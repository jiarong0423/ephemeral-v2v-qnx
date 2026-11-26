/* libm_log.h - host instrument: wraps sin/cos of the w2trace program, records every distinct input (as the 64-bit pattern) and writes libm_inputs.txt at exit.
   Included with -include after <math.h>; the wrapped functions return the host libm result unchanged. */
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define LL_CAP (1u << 21)
static uint64_t ll_s[LL_CAP], ll_c[LL_CAP];
static unsigned ll_ns, ll_nc;
static unsigned long ll_calls_s, ll_calls_c;
static uint64_t ll_bits(double x) { uint64_t b; memcpy(&b, &x, 8); return b; }
static int ll_add(uint64_t *t, unsigned *n, uint64_t b) {
    uint64_t key = b ? b : 0x8000000000000001ull;   /* 0.0 is stored under a marker; the marker is never a real double input here */
    unsigned i = (unsigned)((key * 11400714819323198485ull) >> 43) & (LL_CAP - 1);
    for (;;) { if (t[i] == 0) { t[i] = key; (*n)++; return 1; } if (t[i] == key) return 0; i = (i + 1) & (LL_CAP - 1); }
}
static void ll_dump(void) {
    FILE *f = fopen("libm_inputs.txt", "w"); if (!f) return;
    for (unsigned i = 0; i < LL_CAP; i++) if (ll_s[i]) fprintf(f, "S %016llx\n", (unsigned long long)(ll_s[i] == 0x8000000000000001ull ? 0 : ll_s[i]));
    for (unsigned i = 0; i < LL_CAP; i++) if (ll_c[i]) fprintf(f, "C %016llx\n", (unsigned long long)(ll_c[i] == 0x8000000000000001ull ? 0 : ll_c[i]));
    fclose(f);
    fprintf(stderr, "[libm_log] sin calls %lu distinct %u; cos calls %lu distinct %u\n", ll_calls_s, ll_ns, ll_calls_c, ll_nc);
}
static double ll_sin(double x) { if (!ll_calls_s && !ll_calls_c) atexit(ll_dump); ll_calls_s++; ll_add(ll_s, &ll_ns, ll_bits(x)); return sin(x); }
static double ll_cos(double x) { if (!ll_calls_s && !ll_calls_c) atexit(ll_dump); ll_calls_c++; ll_add(ll_c, &ll_nc, ll_bits(x)); return cos(x); }
#define sin(x) ll_sin(x)
#define cos(x) ll_cos(x)
