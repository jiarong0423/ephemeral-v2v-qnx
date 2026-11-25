//! C interface of `path.rs` (J11, feature `fix_equiv_bb`). `Path` is `repr(C)` and `StepDone` packed; C checks the layout with `v2v_rs_path_layout`
//! (tests/diff_harness_path.c). The signature is answered by C (OpenSSL) through `CStepVerifier`.
use crate::path::*;
use crate::state::Cert;

/// `step_verify(pubkey65, step_done)` returns 1 for "key usable and signature valid", else 0.
#[repr(C)]
pub struct CStepVerifier {
    pub step_verify: Option<unsafe extern "C" fn(*const u8, *const StepDone) -> i32>,
}

impl StepVerifier for CStepVerifier {
    fn step_verify(&mut self, pubkey: &[u8; 65], sd: &StepDone) -> bool {
        match self.step_verify {
            // SAFETY: the C callback reads 65 key bytes and one step done; both live for the call.
            Some(f) => unsafe { f(pubkey.as_ptr(), sd as *const StepDone) != 0 },
            None => false,
        }
    }
}

/// out[0] size of Path, [1] offset of done_mask, [2] offset of progress_us, [3] size of StepDone.
/// # Safety
/// `out` points to 4 writable u64 values.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_path_layout(out: *mut u64) {
    use core::mem::{offset_of, size_of};
    let v = [size_of::<Path>() as u64, offset_of!(Path, done_mask) as u64, offset_of!(Path, progress_us) as u64, size_of::<StepDone>() as u64];
    for (i, x) in v.iter().enumerate() {
        // SAFETY: the caller guarantees 4 writable values.
        unsafe { *out.add(i) = *x };
    }
    // SAFETY: as above (one writable value at least).
    unsafe { crate::b4_link_check(out) };
}

/// C `v2v_path_begin`: 0 or 1 (`P_INVAL`).
/// # Safety
/// `p` points to a writable `Path`; `owners` to `n` u32 values when `n` > 0.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_path_begin(p: *mut Path, self_id: u32, round: u32, plan_hash: u32, owners: *const u32, n: i32, now_us: u64) -> i32 {
    // SAFETY: the caller guarantees a valid, exclusive Path.
    let path = unsafe { &mut *p };
    if n < 0 || n as usize > PATH_MAX_STEPS {
        *path = Path::zero();
        return P_INVAL;
    }
    let own: &[u32] = if n == 0 { &[] } else { unsafe { core::slice::from_raw_parts(owners, n as usize) } };
    path.begin(self_id, round, plan_hash, own, now_us)
}

/// C `v2v_path_step_done` (neutral result codes, see path.rs).
/// # Safety
/// `p` a writable Path, `sd` one step done, `certs` `ncert` certificates, `ver` a verifier.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_path_step_done(p: *mut Path, sd: *const StepDone, certs: *const Cert, ncert: i32, now_us: u64, ver: *mut CStepVerifier) -> i32 {
    // SAFETY: the caller guarantees the pointers; StepDone and Cert are packed (alignment 1).
    let (path, s, vf) = unsafe { (&mut *p, core::ptr::read_unaligned(sd), &mut *ver) };
    let n = if ncert <= 0 { 0 } else { ncert as usize };
    // SAFETY: the caller guarantees `ncert` readable certificates.
    let cs: &[Cert] = if n == 0 { &[] } else { unsafe { core::slice::from_raw_parts(certs, n) } };
    path.step_done(&s, cs, now_us, vf)
}

/// C `v2v_path_may_move`: 0 hold, 1 go, 2 help; -1 / -2 / -3 for C -EINVAL / -EACCES / -EALREADY.
/// # Safety
/// `p` points to a writable Path.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_path_may_move(p: *mut Path, k: i32, now_us: u64) -> i32 {
    // SAFETY: the caller guarantees a valid, exclusive Path.
    unsafe { &mut *p }.may_move(k, now_us)
}
