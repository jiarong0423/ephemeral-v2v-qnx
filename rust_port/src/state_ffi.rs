//! C interface of the stage 2 port (cache, certificates). With `planner_ffi.rs` and `lib.rs`, the only `unsafe` code of the crate besides the libm
//! wrappers: these functions receive raw pointers from C. Everything they call is safe Rust. One wrapper per ported function, named `v2v_rs_<name>`.
//! The structures `Device`, `CacheSlot`, `CertSlot`, `Job` are `repr(C)`; the harness (tests/diff_harness_state.c) mirrors them and checks the layout
//! (`v2v_rs_state_layout`). The verifier is a table of three C function pointers (the harness fills them with the real OpenSSL code of the C file).
use crate::state::*;
use crate::Frame;

/// Signature work done by C (OpenSSL). Each function returns 1 for yes, 0 for no.
#[repr(C)]
pub struct CVerifier {
    pub ca_verify: Option<unsafe extern "C" fn(*const Cert) -> i32>,
    pub key_usable: Option<unsafe extern "C" fn(*const u8) -> i32>,
    pub frame_verify: Option<unsafe extern "C" fn(*const u8, *const SignedFrame) -> i32>,
}

impl Verifier for CVerifier {
    fn ca_verify(&mut self, cert: &Cert) -> bool {
        match self.ca_verify {
            // SAFETY: the C function is supplied by the caller of the FFI wrappers and reads one 145-byte certificate.
            Some(f) => unsafe { f(cert as *const Cert) == 1 },
            None => false,
        }
    }
    fn key_usable(&mut self, pubkey: &[u8; 65]) -> bool {
        match self.key_usable {
            // SAFETY: as above; reads 65 bytes.
            Some(f) => unsafe { f(pubkey.as_ptr()) == 1 },
            None => false,
        }
    }
    fn frame_verify(&mut self, pubkey: &[u8; 65], sf: &SignedFrame) -> bool {
        match self.frame_verify {
            // SAFETY: as above; reads 65 bytes and one 138-byte signed frame.
            Some(f) => unsafe { f(pubkey.as_ptr(), sf as *const SignedFrame) == 1 },
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
pub unsafe extern "C" fn v2v_rs_state_layout(out: *mut u64) {
    use core::mem::{offset_of, size_of};
    let v = [
        size_of::<Device>() as u64,
        offset_of!(Device, certs) as u64,
        offset_of!(Device, unknown_id) as u64,
        offset_of!(Device, unknown_us) as u64,
        offset_of!(Device, ca_ok) as u64,
        offset_of!(Device, ca_ok_next) as u64,
        offset_of!(Device, ca_pub) as u64,
        offset_of!(Device, total_evicted) as u64,
        offset_of!(Device, max_evict_lateness_us) as u64,
        offset_of!(Device, last_evict_lateness_us) as u64,
        size_of::<CacheSlot>() as u64,
        size_of::<CertSlot>() as u64,
        offset_of!(CertSlot, admitted_us) as u64,
        offset_of!(CertSlot, last_frame) as u64,
        offset_of!(CertSlot, have_frame) as u64,
        offset_of!(CertSlot, pubkey) as u64,
        size_of::<Job>() as u64,
        offset_of!(Job, key) as u64,
        offset_of!(Job, j) as u64,
        size_of::<Cert>() as u64,
        size_of::<SignedFrame>() as u64,
        size_of::<Join>() as u64,
    ];
    for (i, x) in v.iter().enumerate() {
        // SAFETY: `out` has room for 32 values (the list above has 22).
        unsafe { *out.add(i) = *x };
    }
    // QG-46 candidate fix: index 22 = offset of CertSlot.cert_vtype, index 23 = 1 for the negative control without the later-frame check.
    // Without the feature both stay as the caller filled them (C fills 0xFF..), so a C/Rust mismatch stops at the layout check.
    #[cfg(feature = "fix_vtype")]
    {
        // SAFETY: as above (indices 22 and 23 < 32).
        unsafe {
            *out.add(22) = offset_of!(CertSlot, cert_vtype) as u64;
            *out.add(23) = if cfg!(feature = "fix_vtype_noframe") { 1 } else { 0 };
        }
    }
    // J8: candidate-fix set of the C program (link and value check; no-op in a default library)
    // SAFETY: `out` has room for at least one value.
    unsafe { crate::b4_link_check(out) };
}

/// Reset the device state (all slots free, no CA key).
/// # Safety
/// `d` points to a writable `Device` (size from `v2v_rs_state_layout`, aligned to 8).
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_dev_reset(d: *mut Device) {
    // SAFETY: the caller guarantees the memory.
    unsafe { core::ptr::write(d, Device::new()) };
}

/// # Safety
/// `d` points to a `Device`, `f` to a 56-byte frame.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_cache_upsert(d: *mut Device, f: *const Frame, now_us: u64, pid: i32, uid: u32, quota: i32) -> i32 {
    // SAFETY: the caller guarantees the pointers.
    let (dev, fr) = unsafe { (&mut *d, rd(f)) };
    dev.cache_upsert(&fr, now_us, pid, uid, quota != 0)
}

/// # Safety
/// `d` points to a `Device`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_cache_sweep(d: *mut Device, now_us: u64) -> u32 {
    // SAFETY: the caller guarantees the pointer.
    unsafe { &mut *d }.cache_sweep(now_us)
}

/// # Safety
/// `d` points to a `Device`, `c` to a 145-byte certificate.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_cert_admit(d: *const Device, c: *const Cert, now_s: u32) -> i32 {
    // SAFETY: the caller guarantees the pointers.
    let (dev, cert) = unsafe { (&*d, rd(c)) };
    dev.cert_admit(&cert, now_s)
}

/// # Safety
/// `c` points to a 145-byte certificate, `out` to 8 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_cert_digest(c: *const Cert, out: *mut u8) {
    // SAFETY: the caller guarantees the pointers.
    let dg = cert_digest(&unsafe { rd(c) });
    for (i, b) in dg.iter().enumerate() {
        // SAFETY: 8 writable bytes.
        unsafe { *out.add(i) = *b };
    }
}

/// # Safety
/// `d` points to a `Device`, `j` to a 283-byte join, `v` to a `CVerifier`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_cert_join(d: *mut Device, j: *const Join, now_us: u64, pid: i32, uid: u32, v: *mut CVerifier) -> i32 {
    // SAFETY: the caller guarantees the pointers.
    let (dev, jn, ver) = unsafe { (&mut *d, rd(j), &mut *v) };
    dev.cert_join(&jn, now_us, pid, uid, ver)
}

/// # Safety
/// `d` points to a `Device`, `sf` to a 138-byte signed frame, `v` to a `CVerifier`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_signed_upsert(d: *mut Device, sf: *const SignedFrame, now_us: u64, pid: i32, uid: u32, v: *mut CVerifier) -> i32 {
    // SAFETY: the caller guarantees the pointers.
    let (dev, s, ver) = unsafe { (&mut *d, rd(sf), &mut *v) };
    dev.signed_upsert(&s, now_us, pid, uid, ver)
}

/// # Safety
/// `d` points to a `Device`, `j` to a join, `w` to a `Job`, `v` to a `CVerifier`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_join_prepare(d: *mut Device, j: *const Join, now_us: u64, pid: i32, uid: u32, w: *mut Job, v: *mut CVerifier) -> i32 {
    // SAFETY: the caller guarantees the pointers.
    let (dev, jn, job, ver) = unsafe { (&mut *d, rd(j), &mut *w, &mut *v) };
    dev.join_prepare(&jn, now_us, pid, uid, job, ver)
}

/// # Safety
/// `d` points to a `Device`, `sf` to a signed frame, `w` to a `Job`, `v` to a `CVerifier`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_frame_prepare(d: *mut Device, sf: *const SignedFrame, now_us: u64, pid: i32, uid: u32, w: *mut Job, v: *mut CVerifier) -> i32 {
    // SAFETY: the caller guarantees the pointers.
    let (dev, s, job, ver) = unsafe { (&mut *d, rd(sf), &mut *w, &mut *v) };
    dev.frame_prepare(&s, now_us, pid, uid, job, ver)
}

/// # Safety
/// `d` points to a `Device`, `w` to a `Job`, `v` to a `CVerifier`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_verify_job_run(d: *const Device, w: *mut Job, v: *mut CVerifier) {
    // SAFETY: the caller guarantees the pointers.
    let (dev, job, ver) = unsafe { (&*d, &mut *w, &mut *v) };
    dev.verify_job_run(job, ver);
}

/// # Safety
/// `d` points to a `Device`, `w` to a `Job`, `v` to a `CVerifier`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_verify_commit(d: *mut Device, w: *mut Job, now_us: u64, pid: i32, uid: u32, v: *mut CVerifier) -> i32 {
    // SAFETY: the caller guarantees the pointers.
    let (dev, job, ver) = unsafe { (&mut *d, &mut *w, &mut *v) };
    dev.verify_commit(job, now_us, pid, uid, ver)
}

/// # Safety
/// `w` points to a `Job`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_verify_job_free(w: *mut Job) {
    // SAFETY: the caller guarantees the pointer.
    Device::verify_job_free(unsafe { &mut *w });
}

/// # Safety
/// `d` points to a `Device`, `ids` to `max` writable u32 values (4-byte aligned).
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_members_active(d: *const Device, now_us: u64, ids: *mut u32, max: i32) -> i32 {
    let mut tmp = [0u32; crate::MAX_ACTIVE_NODES];
    let m = if max < 0 { 0 } else { (max as usize).min(crate::MAX_ACTIVE_NODES) };
    // SAFETY: the caller guarantees the pointer.
    let n = unsafe { &*d }.members_active(now_us, &mut tmp[..m]);
    for (i, x) in tmp.iter().enumerate().take(n as usize) {
        // SAFETY: the caller guarantees `max` writable values and n <= max.
        unsafe { *ids.add(i) = *x };
    }
    n
}

/// # Safety
/// `d` points to a `Device`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_members_silent(d: *const Device, now_us: u64) -> i32 {
    // SAFETY: the caller guarantees the pointer.
    unsafe { &*d }.members_silent(now_us)
}

/// # Safety
/// `d` points to a `Device`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_unknown_recent(d: *const Device, now_us: u64) -> i32 {
    // SAFETY: the caller guarantees the pointer.
    unsafe { &*d }.unknown_recent(now_us)
}

/// # Safety
/// `d` points to a `Device`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_cert_sweep(d: *mut Device, now_s: u32) -> u32 {
    // SAFETY: the caller guarantees the pointer.
    unsafe { &mut *d }.cert_sweep(now_s)
}

/// # Safety
/// `d` points to a `Device`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_cert_reset(d: *mut Device) {
    // SAFETY: the caller guarantees the pointer.
    unsafe { &mut *d }.cert_reset();
}
