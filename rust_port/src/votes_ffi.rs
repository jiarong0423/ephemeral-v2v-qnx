//! C interface of the stage 3 votes port. With the other `*_ffi.rs` files and `lib.rs`, the only `unsafe` code of the crate besides the libm wrappers:
//! these functions receive raw pointers from C. Everything they call is safe Rust. One wrapper per ported function, named `v2v_rs_vote_*`.
//! `Votes`, `VoteSlot`, `VoteReport` are `repr(C)`; the harness (tests/diff_harness_votes.c) mirrors them and checks the layout (`v2v_rs_votes_layout`).
//! The device state (`Device`) is the stage 2 one (`state_ffi.rs`).
use crate::state::{Cert, Device};
use crate::votes::*;
use crate::{Frame, Vote};

/// Signature work done by C (OpenSSL): `vote_verify(pubkey65, vote)` returns 1 for "key usable and signature valid", else 0.
#[repr(C)]
pub struct CVoteVerifier {
    pub vote_verify: Option<unsafe extern "C" fn(*const u8, *const Vote) -> i32>,
}

impl VoteVerifier for CVoteVerifier {
    fn vote_verify(&mut self, pubkey: &[u8; 65], v: &Vote) -> bool {
        match self.vote_verify {
            // SAFETY: the C function is supplied by the caller of the FFI wrappers; it reads 65 bytes and one 106-byte vote.
            Some(f) => unsafe { f(pubkey.as_ptr(), v as *const Vote) == 1 },
            None => false,
        }
    }
}

/// # Safety
/// `p` must be valid for reading one `T`.
unsafe fn rd<T: Copy>(p: *const T) -> T {
    // SAFETY: the caller guarantees `p` is valid; read_unaligned also accepts packed structs.
    unsafe { core::ptr::read_unaligned(p) }
}

/// Sizes and offsets of the shared structures (the harness compares them with its mirror).
/// # Safety
/// `out` points to 32 writable `u64`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_votes_layout(out: *mut u64) {
    use core::mem::{offset_of, size_of};
    let v = [
        size_of::<Votes>() as u64,
        offset_of!(Votes, round) as u64,
        size_of::<VoteSlot>() as u64,
        offset_of!(VoteSlot, v) as u64,
        size_of::<VoteReport>() as u64,
        offset_of!(VoteReport, vote_round) as u64,
        offset_of!(VoteReport, vote_count) as u64,
        offset_of!(VoteReport, silent_members) as u64,
        size_of::<Vote>() as u64,
    ];
    for (i, x) in v.iter().enumerate() {
        // SAFETY: `out` has room for 32 values (the list above has 9).
        unsafe { *out.add(i) = *x };
    }
    // J8: candidate-fix set of the C program (link and value check; no-op in a default library)
    // SAFETY: `out` has room for at least one value.
    unsafe { crate::b4_link_check(out) };
}

/// # Safety
/// `s` points to a writable `Votes`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_vote_reset(s: *mut Votes) {
    // SAFETY: the caller guarantees the memory.
    unsafe { &mut *s }.reset();
}

/// # Safety
/// `s` points to a `Votes`, `d` to a `Device`, `v` to a 106-byte vote, `ver` to a `CVoteVerifier`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_vote_post(s: *mut Votes, d: *mut Device, v: *const Vote, now_us: u64, ver: *mut CVoteVerifier) -> i32 {
    // SAFETY: the caller guarantees the pointers.
    let (vs, dev, vote, vf) = unsafe { (&mut *s, &mut *d, rd(v), &mut *ver) };
    vs.post(dev, &vote, now_us, vf)
}

/// # Safety
/// `s` points to a `Votes`, `d` to a `Device`, `out` to a writable `VoteReport`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_vote_fill_report_at(s: *const Votes, d: *const Device, now_us: u64, out: *mut VoteReport) {
    // SAFETY: the caller guarantees the pointers.
    let (vs, dev) = unsafe { (&*s, &*d) };
    let rep = vs.fill_report_at(dev, now_us);
    // SAFETY: `out` is writable for one VoteReport.
    unsafe { core::ptr::write_unaligned(out, rep) };
}

/// # Safety
/// `fr` points to `n` frames (56 bytes each); `out` to 8 writable bytes. `n <= 0` gives zeros (as C).
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_input_digest(fr: *const Frame, n: i32, out: *mut u8) {
    let m = if n <= 0 { 0 } else { (n as usize).min(DIGEST_MAX_FRAMES + 1) };
    let mut frames = [Frame::default(); DIGEST_MAX_FRAMES + 1];
    for (i, f) in frames.iter_mut().enumerate().take(m) {
        // SAFETY: the caller guarantees `n` readable frames.
        *f = unsafe { rd(fr.add(i)) };
    }
    let d = if m > DIGEST_MAX_FRAMES { [0u8; 8] } else { input_digest(&frames[..m]) };
    for (i, b) in d.iter().enumerate() {
        // SAFETY: 8 writable bytes.
        unsafe { *out.add(i) = *b };
    }
}

/// # Safety
/// `fd` points to 8 bytes, `ids` to `n` u32 values (4-byte aligned), `out` to 8 writable bytes. `n` above 16 is cut to 16 as in C.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_member_digest(fd: *const u8, ids: *const u32, n: i32, out: *mut u8) {
    let mut f = [0u8; 8];
    for (i, b) in f.iter_mut().enumerate() {
        // SAFETY: 8 readable bytes.
        *b = unsafe { *fd.add(i) };
    }
    let mut tmp = [0u32; crate::MAX_ACTIVE_NODES];
    let m = if n <= 0 { 0 } else { (n as usize).min(crate::MAX_ACTIVE_NODES) };
    for (i, x) in tmp.iter_mut().enumerate().take(m) {
        // SAFETY: the caller guarantees `n` readable values (only the first 16 are read).
        *x = unsafe { *ids.add(i) };
    }
    let d = member_digest(&f, &tmp[..m]);
    for (i, b) in d.iter().enumerate() {
        // SAFETY: 8 writable bytes.
        unsafe { *out.add(i) = *b };
    }
}

/// # Safety
/// `v` points to a vote, `certs` to `ncert` certificates (145 bytes each), `ver` to a `CVoteVerifier`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_vote_sig_ok(v: *const Vote, certs: *const Cert, ncert: i32, ver: *mut CVoteVerifier) -> i32 {
    // SAFETY: the caller guarantees the pointers; Cert and Vote are packed (alignment 1), so a slice over C memory is valid.
    let (vote, vf) = unsafe { (rd(v), &mut *ver) };
    let n = if ncert <= 0 { 0 } else { ncert as usize };
    // SAFETY: the caller guarantees `ncert` readable certificates.
    let cs: &[Cert] = if n == 0 { &[] } else { unsafe { core::slice::from_raw_parts(certs, n) } };
    vote_sig_ok(&vote, cs, vf) as i32
}

/// Returns the count; `ids` gets the first `max` ids (at most 64 are supported here).
/// # Safety
/// `mine` points to a vote, `votes` to `nv` votes, `ids` to `max` writable u32 values (4-byte aligned).
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_agree_dissenters(mine: *const Vote, votes: *const Vote, nv: i32, ids: *mut u32, max: i32) -> i32 {
    // SAFETY: the caller guarantees the pointers; Vote is packed (alignment 1).
    let m = unsafe { rd(mine) };
    let n = if nv <= 0 { 0 } else { nv as usize };
    // SAFETY: the caller guarantees `nv` readable votes.
    let vs: &[Vote] = if n == 0 { &[] } else { unsafe { core::slice::from_raw_parts(votes, n) } };
    let mut tmp = [0u32; 64];
    let mx = if max <= 0 { 0 } else { (max as usize).min(64) };
    let k = agree_dissenters(&m, vs, &mut tmp[..mx]);
    for (i, x) in tmp.iter().enumerate().take(mx.min(k.max(0) as usize)) {
        // SAFETY: the caller guarantees `max` writable values.
        unsafe { *ids.add(i) = *x };
    }
    k
}
