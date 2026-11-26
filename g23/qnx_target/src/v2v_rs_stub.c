/* v2v_rs_stub.c - only linked in the Rust-backed variant (-DV2V_USE_RUST).
 * The precompiled Rust core library refers to an unwinding hook that the abort-on-panic build never calls; this empty
 * definition satisfies the linker (the diff harnesses in ../rust_port/tests do the same). */
void rust_eh_personality(void) {}
