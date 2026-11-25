//! Stage 2 of the Rust track: the TTL cache with its upsert core and sweep, and the certificate / signed-frame / join state machine
//! (`qnx_target/src/v2v_ttl_resmgr.c`, lines 209-345 and 386-870), with the state passed explicitly (`Device`) instead of C globals.
//!
//! What stays in C: the ECDSA and key work (OpenSSL). The logic around it asks a `Verifier` for the three signature facts it needs
//! (CA signature valid, public key usable, frame signature valid); in the differential harness the verifier is the real OpenSSL code of
//! the C file, so the Rust decisions are compared with the C decisions on real signatures, valid and broken.
//! Not ported (printing, counters that only feed the log, locks): the "[v2v_ttl SWEEP]" lines, `g_max_evict_lateness_us` is kept.
//! Every function maps to one C function (see `rust_port/MAPPING.md`). Written for Rust 1.85: edition 2021, no dependencies, safe code.
use crate::geom::c_sqrt;
use crate::planner::sha256;
use crate::{frame_check, Frame, FRAME_BAD_CRC, FRAME_INVALID, MAX_ACTIVE_NODES};

// ---- result codes: C returns negative errno values, whose numbers differ between platforms; the port returns these neutral codes ----
pub const R_OK: i32 = 0;
pub const R_INVAL: i32 = 1; // C -EINVAL
pub const R_BADMSG: i32 = 2; // C -EBADMSG
pub const R_PERM: i32 = 3; // C -EPERM
pub const R_ALREADY: i32 = 4; // C -EALREADY
pub const R_NOSPC: i32 = 5; // C -ENOSPC
pub const R_DOM: i32 = 6; // C -EDOM
pub const R_ACCES: i32 = 7; // C -EACCES
pub const R_NOMSG: i32 = 8; // C -ENOMSG
pub const R_TIME: i32 = 9; // C -ETIME
pub const R_NEED_VERIFY: i32 = 100; // C V2V_NEED_VERIFY (1)

// ---- constants ----
pub const DEFAULT_TTL_MS: u32 = 300;
pub const MAX_IDS_PER_SENDER: i32 = 4;
pub const MAX_SPEED_CMS: f64 = 1500.0;
pub const POS_JITTER_CM: f64 = 50.0;
pub const CERT_MAGIC: u16 = 0x4543;
pub const CERT_VERSION: u8 = 1;
pub const FRAME_MAX_AHEAD_MS: i32 = 200;
pub const UNKNOWN_HOLD_US: u64 = 1_000_000;
pub const MEMBER_SILENT_MS: u64 = 3000;
pub const CERT_SLOTS: usize = MAX_ACTIVE_NODES;
pub const CA_OK_SLOTS: usize = 16;
pub const UNKNOWN_SLOTS: usize = 8;

// ---- wire structures (packed like the C ones; sizes asserted) ----
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Cert {
    pub magic: u16,
    pub version: u8,
    pub vehicle_type: u8,
    pub pseudo_id: u32,
    pub not_before_s: u32,
    pub not_after_s: u32,
    pub pubkey: [u8; 65],
    pub issuer_sig: [u8; 64],
}
const _: () = assert!(core::mem::size_of::<Cert>() == 145);

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct SignedFrame {
    pub frame: Frame,
    pub cert_digest: [u8; 8],
    pub seq: u16,
    pub chain: [u8; 8],
    pub sig: [u8; 64],
}
const _: () = assert!(core::mem::size_of::<SignedFrame>() == 138);

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Join {
    pub cert: Cert,
    pub sf: SignedFrame,
}
const _: () = assert!(core::mem::size_of::<Join>() == 283);

impl Cert {
    pub const fn zero() -> Cert {
        Cert { magic: 0, version: 0, vehicle_type: 0, pseudo_id: 0, not_before_s: 0, not_after_s: 0, pubkey: [0; 65], issuer_sig: [0; 64] }
    }
    /// The 145 wire bytes (little-endian fields).
    pub fn to_bytes(&self) -> [u8; 145] {
        let mut b = [0u8; 145];
        let (magic, pid, nb, na) = (self.magic, self.pseudo_id, self.not_before_s, self.not_after_s);
        b[0..2].copy_from_slice(&magic.to_le_bytes());
        b[2] = self.version;
        b[3] = self.vehicle_type;
        b[4..8].copy_from_slice(&pid.to_le_bytes());
        b[8..12].copy_from_slice(&nb.to_le_bytes());
        b[12..16].copy_from_slice(&na.to_le_bytes());
        let pk = self.pubkey;
        b[16..81].copy_from_slice(&pk);
        let sg = self.issuer_sig;
        b[81..145].copy_from_slice(&sg);
        b
    }
}

impl SignedFrame {
    pub const fn zero() -> SignedFrame {
        SignedFrame {
            frame: Frame {
                magic: 0,
                protocol_ver: 0,
                vehicle_type: 0,
                pseudo_id: 0,
                ttl_ms: 0,
                t_ms: 0,
                seg_id: 0,
                line_count: 0,
                s_cm: 0,
                d_cm: 0,
                heading_cdeg: 0,
                len_dm: 0,
                wid_dm: 0,
                line: [crate::Line { s1_cm: 0, d1_cm: 0, s2_cm: 0, d2_cm: 0 }; 4],
                crc16: 0,
            },
            cert_digest: [0; 8],
            seq: 0,
            chain: [0; 8],
            sig: [0; 64],
        }
    }
}

impl Join {
    pub const fn zero() -> Join {
        Join { cert: Cert::zero(), sf: SignedFrame::zero() }
    }
}

// ---- state ----
/// C `ttl_cache_slot_t`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CacheSlot {
    pub in_use: i32,
    pub frame: Frame,
    pub expires_at_us: u64,
    pub sender_pid: i32,
    pub sender_uid: u32,
}

impl CacheSlot {
    pub const fn zero() -> CacheSlot {
        CacheSlot { in_use: 0, frame: SignedFrame::zero().frame, expires_at_us: 0, sender_pid: 0, sender_uid: 0 }
    }
}

/// C `v2v_cert_slot_t`; the OpenSSL key object is represented by the 65-byte public key it was made from (`has_key`, `pubkey`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CertSlot {
    pub in_use: i32,
    pub digest: [u8; 8],
    pub pseudo_id: u32,
    pub not_before_s: u32,
    pub not_after_s: u32,
    pub last_gen_ms: u32,
    pub have_gen: i32,
    pub proven: i32,
    pub admitted_us: u64,
    pub last_ok_us: u64,
    pub last_frame: Frame,
    pub have_frame: i32,
    pub voted: i32,
    pub has_key: i32,
    pub pubkey: [u8; 65],
    /// QG-46 candidate fix (feature `fix_vtype`, C `-DV2V_FIX_VTYPE`): the certificate's vehicle_type; every frame under it must claim it.
    #[cfg(feature = "fix_vtype")]
    pub cert_vtype: u32,
}

impl CertSlot {
    pub const fn zero() -> CertSlot {
        CertSlot {
            in_use: 0,
            digest: [0; 8],
            pseudo_id: 0,
            not_before_s: 0,
            not_after_s: 0,
            last_gen_ms: 0,
            have_gen: 0,
            proven: 0,
            admitted_us: 0,
            last_ok_us: 0,
            last_frame: SignedFrame::zero().frame,
            have_frame: 0,
            voted: 0,
            has_key: 0,
            pubkey: [0; 65],
            #[cfg(feature = "fix_vtype")]
            cert_vtype: 0,
        }
    }
}

/// C `v2v_verify_job_t`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Job {
    pub kind: i32,
    pub ca_ok: i32,
    pub sig_ok: i32,
    pub has_key: i32,
    pub key: [u8; 65],
    pub j: Join,
}

impl Job {
    pub const fn zero() -> Job {
        Job { kind: 0, ca_ok: 0, sig_ok: 0, has_key: 0, key: [0; 65], j: Join::zero() }
    }
}

/// The signature facts the logic needs; C answers them with OpenSSL.
pub trait Verifier {
    /// C `v2v_verify_raw(g_ca_pub, cert, offsetof(issuer_sig), issuer_sig)`; only asked when a CA key is configured.
    fn ca_verify(&mut self, cert: &Cert) -> bool;
    /// C `v2v_key_from_pub(pubkey) != NULL`: the 65 bytes are a usable P-256 public key.
    fn key_usable(&mut self, pubkey: &[u8; 65]) -> bool;
    /// C `v2v_verify_raw(key, sf, offsetof(sig), sf->sig)` with the key made from `pubkey`.
    fn frame_verify(&mut self, pubkey: &[u8; 65], sf: &SignedFrame) -> bool;
}

/// All the state that C keeps in globals: `g_ttl_cache`, `g_certs`, `g_unknown_*`, `g_ca_ok*`, `g_ca_pub` (present or not) and the eviction counters.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Device {
    pub cache: [CacheSlot; MAX_ACTIVE_NODES],
    pub certs: [CertSlot; CERT_SLOTS],
    pub unknown_id: [u32; UNKNOWN_SLOTS],
    pub unknown_us: [u64; UNKNOWN_SLOTS],
    pub ca_ok: [[u8; 8]; CA_OK_SLOTS],
    pub ca_ok_next: i32,
    pub ca_pub: i32,
    pub total_evicted: u32,
    pub max_evict_lateness_us: u32,
    pub last_evict_lateness_us: u32,
}

/// C `v2v_secure_zero(&slot)`: zero a slot in a way the optimiser may not drop (C uses a volatile loop). `black_box` and the fence are the safe-Rust
/// means for that; the differential harness compares the memory after the call, it cannot see whether a build removed the store (not verified).
fn wipe_cache(s: &mut CacheSlot) {
    *s = CacheSlot::zero();
    core::hint::black_box(&*s);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

fn wipe_cert(s: &mut CertSlot) {
    *s = CertSlot::zero();
    core::hint::black_box(&*s);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

fn gen_ms_of(sf: &SignedFrame) -> u32 {
    // C `frame_gen_ms`
    let (seq, t) = (sf.seq, sf.frame.t_ms);
    ((seq as u32) << 16) | t as u32
}

fn gen_ms(now_us: u64) -> u32 {
    // C `v2v_gen_ms`
    (now_us / 1000) as u32
}

/// C `v2v_cert_digest`: the last 8 bytes of SHA-256 over the 145 certificate bytes.
pub fn cert_digest(c: &Cert) -> [u8; 8] {
    let h = sha256(&c.to_bytes());
    let mut out = [0u8; 8];
    out.copy_from_slice(&h[24..32]);
    out
}

/// C `cert_cheap_ok`.
fn cert_cheap_ok(c: &Cert, now_s: u32) -> i32 {
    let (nb, na, pid) = (c.not_before_s, c.not_after_s, c.pseudo_id);
    if c.magic != CERT_MAGIC || c.version != CERT_VERSION || na <= nb || pid == 0 {
        return R_INVAL;
    }
    if now_s < nb || now_s >= na {
        return R_ACCES;
    }
    R_OK
}

impl Device {
    pub const fn new() -> Device {
        Device {
            cache: [CacheSlot::zero(); MAX_ACTIVE_NODES],
            certs: [CertSlot::zero(); CERT_SLOTS],
            unknown_id: [0; UNKNOWN_SLOTS],
            unknown_us: [0; UNKNOWN_SLOTS],
            ca_ok: [[0; 8]; CA_OK_SLOTS],
            ca_ok_next: 0,
            ca_pub: 0,
            total_evicted: 0,
            max_evict_lateness_us: 0,
            last_evict_lateness_us: 0,
        }
    }

    // ------------------------------------------------------------------ TTL cache
    /// C `cache_upsert_core` (`quota` = C's `quota` argument; `v2v_cache_upsert_from` is quota true, `v2v_cache_upsert` is pid 0, uid 0, quota true).
    pub fn cache_upsert(&mut self, incoming: &Frame, now_us: u64, pid: i32, uid: u32, quota: bool) -> i32 {
        match frame_check(incoming) {
            FRAME_INVALID => return R_INVAL,
            FRAME_BAD_CRC => return R_BADMSG,
            _ => {}
        }
        let inc_id = incoming.pseudo_id;
        // A slot whose frame has already expired (even if the sweep has not run yet) counts as free.
        let mut target: i32 = -1;
        let mut owned: i32 = 0; // live slots already held by this sender, other IDs than the incoming one
        for i in 0..MAX_ACTIVE_NODES {
            let s = &self.cache[i];
            let live = s.in_use != 0 && now_us < s.expires_at_us;
            let sid = s.frame.pseudo_id;
            if live && sid == inc_id {
                target = i as i32;
                break;
            }
            if live && s.sender_pid == pid && s.sender_uid == uid {
                owned += 1;
            }
            if !live && target == -1 {
                target = i as i32;
            }
        }
        if target < 0 {
            return R_NOSPC;
        }
        let t = target as usize;
        let tsid = self.cache[t].frame.pseudo_id;
        let target_live = self.cache[t].in_use != 0 && now_us < self.cache[t].expires_at_us && tsid == inc_id;
        if quota && !target_live && owned >= MAX_IDS_PER_SENDER {
            return R_NOSPC; // one process may not fill the whole cache
        }
        if !target_live {
            self.cache[t] = CacheSlot::zero();
        }
        if self.cache[t].in_use != 0 {
            if quota && (self.cache[t].sender_pid != pid || self.cache[t].sender_uid != uid) {
                return R_PERM;
            }
            let newer = incoming.t_ms.wrapping_sub(self.cache[t].frame.t_ms) as i16;
            if newer <= 0 {
                return R_ALREADY;
            }
            // a position jump that no vehicle can drive between two frames is refused
            let (is, id) = (incoming.s_cm, incoming.d_cm);
            let (ss, sd) = (self.cache[t].frame.s_cm, self.cache[t].frame.d_cm);
            let ds = is as f64 - ss as f64;
            let dd = id as f64 - sd as f64;
            if c_sqrt(ds * ds + dd * dd) > MAX_SPEED_CMS * (newer as f64 / 1000.0) + POS_JITTER_CM {
                return R_DOM;
            }
        }
        let tm = incoming.ttl_ms as u32;
        let ttl: u32 = if tm < DEFAULT_TTL_MS { tm } else { DEFAULT_TTL_MS };
        let s = &mut self.cache[t];
        s.in_use = 1;
        s.frame = *incoming;
        s.expires_at_us = now_us.wrapping_add(ttl as u64 * 1000);
        s.sender_pid = pid;
        s.sender_uid = uid;
        R_OK
    }

    /// C `v2v_cache_sweep_expired` (without the print).
    pub fn cache_sweep(&mut self, now_us: u64) -> u32 {
        let mut evicted: u32 = 0;
        let mut sweep_max: u32 = 0;
        for i in 0..MAX_ACTIVE_NODES {
            if self.cache[i].in_use != 0 && now_us >= self.cache[i].expires_at_us {
                let late = now_us.wrapping_sub(self.cache[i].expires_at_us) as u32;
                if late > self.max_evict_lateness_us {
                    self.max_evict_lateness_us = late;
                }
                if late > sweep_max {
                    sweep_max = late;
                }
                wipe_cache(&mut self.cache[i]);
                evicted += 1;
                self.total_evicted = self.total_evicted.wrapping_add(1);
            }
        }
        if evicted > 0 {
            self.last_evict_lateness_us = sweep_max;
        }
        evicted
    }

    // ------------------------------------------------------------------ certificates, signed frames
    /// C `cert_by_digest`: index of the slot holding that digest.
    fn cert_by_digest(&self, dg: &[u8; 8]) -> Option<usize> {
        (0..CERT_SLOTS).find(|&i| self.certs[i].in_use != 0 && self.certs[i].digest == *dg)
    }

    /// C `v2v_cert_admit`.
    pub fn cert_admit(&self, c: &Cert, now_s: u32) -> i32 {
        let (nb, na) = (c.not_before_s, c.not_after_s);
        if c.magic != CERT_MAGIC || c.version != CERT_VERSION || na <= nb {
            return R_INVAL;
        }
        let dg = cert_digest(c);
        if let Some(h) = self.cert_by_digest(&dg) {
            return if now_s < self.certs[h].not_after_s { R_OK } else { R_ACCES };
        }
        let rc = cert_cheap_ok(c, now_s);
        if rc != 0 {
            rc
        } else {
            R_NOMSG
        }
    }

    /// C `ca_cached`.
    fn ca_cached(&self, dg: &[u8; 8]) -> bool {
        self.ca_ok.iter().any(|e| *e == *dg)
    }

    /// C `ca_cache_add`.
    fn ca_cache_add(&mut self, dg: &[u8; 8]) {
        if self.ca_cached(dg) {
            return;
        }
        self.ca_ok[self.ca_ok_next as usize] = *dg;
        self.ca_ok_next = (self.ca_ok_next + 1) % CA_OK_SLOTS as i32;
    }

    /// C `member_silent`.
    fn member_silent(&self, i: usize, now_us: u64) -> bool {
        self.certs[i].in_use != 0 && now_us >= self.certs[i].last_ok_us.wrapping_add(MEMBER_SILENT_MS * 1000)
    }

    /// C `v2v_verify_job_run`.
    pub fn verify_job_run(&self, w: &mut Job, v: &mut dyn Verifier) {
        if w.kind == 1 && w.ca_ok < 0 {
            let cert = w.j.cert;
            let isig = cert.issuer_sig;
            w.ca_ok = if self.ca_pub != 0 && crate::sig_s_allowed(&isig) && v.ca_verify(&cert) { 1 } else { 0 };
        }
        if w.kind == 1 && w.ca_ok != 1 {
            w.sig_ok = 0;
            return;
        }
        if w.has_key == 0 && w.kind == 1 {
            let pk = w.j.cert.pubkey;
            if v.key_usable(&pk) {
                w.has_key = 1;
                w.key = pk;
            }
        }
        if w.has_key == 0 {
            w.sig_ok = -2;
            return;
        }
        let sf = w.j.sf;
        let key = w.key;
        let fsig = sf.sig;
        w.sig_ok = if crate::sig_s_allowed(&fsig) && v.frame_verify(&key, &sf) { 1 } else { 0 };
    }

    /// C `v2v_verify_job_free`.
    pub fn verify_job_free(w: &mut Job) {
        w.has_key = 0;
        w.key = [0; 65];
    }

    /// C `cert_join_core`. `done` = signature results of `verify_job_run` (commit); `defer` = where to put the job instead of checking
    /// signatures now (prepare); both `None` = check inline.
    pub fn cert_join_core(&mut self, j: &Join, now_us: u64, pid: i32, uid: u32, done: Option<&mut Job>, defer: Option<&mut Job>, v: &mut dyn Verifier) -> i32 {
        let c = j.cert;
        let sf = j.sf;
        let now_s = (now_us / 1_000_000) as u32;
        let (nb, na, cpid) = (c.not_before_s, c.not_after_s, c.pseudo_id);
        if c.magic != CERT_MAGIC || c.version != CERT_VERSION || na <= nb {
            return R_INVAL;
        }
        let dg = cert_digest(&c);
        let sf_digest = sf.cert_digest;
        let sf_pid = sf.frame.pseudo_id;
        if dg != sf_digest || sf_pid != cpid {
            return R_PERM;
        }
        // QG-46 candidate fix (off by default): the frame's vehicle_type must be the one the CA signed into the certificate (cheap, before any signature work)
        #[cfg(feature = "fix_vtype")]
        if sf.frame.vehicle_type != c.vehicle_type {
            return R_PERM;
        }
        if let Some(h) = self.cert_by_digest(&dg) {
            if now_s >= self.certs[h].not_after_s {
                return R_ACCES;
            }
            let pre = match &done {
                None => -1,
                Some(d) => {
                    if d.sig_ok == 1 {
                        1
                    } else {
                        0
                    }
                }
            };
            return self.signed_upsert_slot(h, &sf, now_us, pid, uid, pre, defer, v);
        }
        let rc = cert_cheap_ok(&c, now_s);
        if rc != 0 {
            return rc;
        }
        let gen = gen_ms_of(&sf);
        let age = gen_ms(now_us).wrapping_sub(gen) as i32;
        let fttl = sf.frame.ttl_ms as u32;
        let ttl = (if fttl < DEFAULT_TTL_MS { fttl } else { DEFAULT_TTL_MS }) as i32;
        if age >= ttl || age < -FRAME_MAX_AHEAD_MS {
            return R_TIME;
        }
        let mut slot: i32 = -1;
        let mut free_slot: i32 = -1;
        let mut silent_slot: i32 = -1;
        for i in 0..CERT_SLOTS {
            if self.certs[i].in_use != 0 && self.certs[i].pseudo_id == cpid {
                slot = i as i32;
            }
            if self.certs[i].in_use == 0 && free_slot < 0 {
                free_slot = i as i32;
            }
            if self.member_silent(i, now_us) && (silent_slot < 0 || self.certs[i].last_ok_us < self.certs[silent_slot as usize].last_ok_us) {
                silent_slot = i as i32;
            }
        }
        if slot >= 0 && nb <= self.certs[slot as usize].not_before_s {
            return R_ALREADY;
        }
        if slot < 0 {
            slot = if free_slot >= 0 { free_slot } else { silent_slot }; // a newer certificate for a member's ID replaces it
        }
        let ca_ok = if self.ca_cached(&dg) {
            1
        } else {
            match &done {
                Some(d) => d.ca_ok,
                None => -1,
            }
        };
        let sig_ok = match &done {
            Some(d) => d.sig_ok,
            None => -1,
        };
        if ca_ok < 0 || (ca_ok == 1 && sig_ok == -1) {
            // signature work still to do
            let mut local = Job::zero();
            let had_defer = defer.is_some();
            let w: &mut Job = match defer {
                Some(d) => d,
                None => &mut local,
            };
            *w = Job::zero();
            w.kind = 1;
            w.j = *j;
            w.ca_ok = ca_ok;
            w.sig_ok = -1;
            if had_defer {
                return R_NEED_VERIFY;
            }
            self.verify_job_run(&mut local, v);
            let rc = self.cert_join_core(j, now_us, pid, uid, Some(&mut local), None, v);
            Device::verify_job_free(&mut local);
            return rc;
        }
        if ca_ok != 1 {
            return R_PERM;
        }
        self.ca_cache_add(&dg); // the CA signature holds whatever the frame: re-presenting costs one SHA-256
        if sig_ok == -2 {
            return R_INVAL;
        }
        if sig_ok != 1 {
            return R_PERM;
        }
        if slot < 0 {
            // proven, but every slot holds a live member: none is pushed out
            self.note_unknown(cpid, now_us);
            return R_NOSPC;
        }
        // the job's key becomes the slot's (C: `done->key`; `done` is always set here, because without it the signature work above has not run)
        let d = match done {
            Some(d) => d,
            None => return R_PERM,
        };
        let (k_has, k_bytes) = (d.has_key, d.key);
        d.has_key = 0;
        d.key = [0; 65];
        let s = slot as usize;
        // G19 / N4 (C -DV2V_FIX_N4): the slot as it was (CertSlot is Copy, the key is its public-key bytes) comes back if the cache refuses the frame
        #[cfg(feature = "fix_n4")]
        let n4_old = self.certs[s];
        self.certs[s] = CertSlot::zero();
        let cs = &mut self.certs[s];
        cs.in_use = 1;
        cs.digest = dg;
        cs.pseudo_id = cpid;
        cs.not_before_s = nb;
        cs.not_after_s = na;
        #[cfg(feature = "fix_vtype")]
        {
            cs.cert_vtype = c.vehicle_type as u32;
        }
        cs.admitted_us = now_us;
        cs.last_ok_us = now_us;
        cs.has_key = k_has;
        cs.pubkey = k_bytes;
        #[cfg(feature = "fix_n4")]
        {
            let rc = self.signed_upsert_slot(s, &sf, now_us, pid, uid, 1, None, v);
            // G19b / N4 renewal reordered (C: the same rule): a renewal whose first frame is not newer than a frame already accepted under the old
            // certificate of this ID was refused by the cache only because the car's own later frame overtook it: the renewal is kept (R_OK)
            if rc == R_ALREADY && n4_old.in_use != 0 && n4_old.pseudo_id == cpid && n4_old.have_gen != 0 && (gen.wrapping_sub(n4_old.last_gen_ms) as i32) <= 0 {
                return R_OK;
            }
            if rc != R_OK {
                self.certs[s] = n4_old; // undo the refused join (C frees the new key here)
            }
            rc
        }
        #[cfg(not(feature = "fix_n4"))]
        self.signed_upsert_slot(s, &sf, now_us, pid, uid, 1, None, v)
    }

    /// C `v2v_cert_join` (inline signature checks).
    pub fn cert_join(&mut self, j: &Join, now_us: u64, pid: i32, uid: u32, v: &mut dyn Verifier) -> i32 {
        self.cert_join_core(j, now_us, pid, uid, None, None, v)
    }

    /// C `note_unknown`.
    fn note_unknown(&mut self, id: u32, now_us: u64) {
        let mut slot = 0usize;
        for i in 0..UNKNOWN_SLOTS {
            if self.unknown_id[i] == id && self.unknown_us[i] != 0 {
                return; // already noted: no refresh
            }
            if self.unknown_us[i] < self.unknown_us[slot] {
                slot = i;
            }
        }
        self.unknown_id[slot] = id;
        self.unknown_us[slot] = now_us;
    }

    /// C `v2v_unknown_recent`.
    pub fn unknown_recent(&self, now_us: u64) -> i32 {
        let mut n = 0;
        for i in 0..UNKNOWN_SLOTS {
            if self.unknown_us[i] == 0 || now_us >= self.unknown_us[i].wrapping_add(UNKNOWN_HOLD_US) {
                continue;
            }
            let mut proven = false;
            for k in 0..CERT_SLOTS {
                if self.certs[k].in_use != 0 && self.certs[k].pseudo_id == self.unknown_id[i] && self.certs[k].proven != 0 {
                    proven = true;
                }
            }
            if !proven {
                n += 1;
            }
        }
        n
    }

    /// C `signed_upsert_any`.
    pub fn signed_upsert_any(&mut self, sf: &SignedFrame, now_us: u64, pid: i32, uid: u32, pre_sig: i32, defer: Option<&mut Job>, v: &mut dyn Verifier) -> i32 {
        let now_s = (now_us / 1_000_000) as u32;
        let dg = sf.cert_digest;
        match self.cert_by_digest(&dg) {
            Some(cs) if now_s < self.certs[cs].not_after_s => self.signed_upsert_slot(cs, sf, now_us, pid, uid, pre_sig, defer, v),
            _ => R_ACCES,
        }
    }

    /// C `v2v_signed_upsert`: signature checked inline.
    pub fn signed_upsert(&mut self, sf: &SignedFrame, now_us: u64, pid: i32, uid: u32, v: &mut dyn Verifier) -> i32 {
        self.signed_upsert_any(sf, now_us, pid, uid, -1, None, v)
    }

    /// C `signed_upsert_slot`. `pre_sig`: 1 = signature already verified, 0 = known bad, -1 = verify (now, or as a job if `defer` is given).
    #[allow(clippy::too_many_arguments)]
    fn signed_upsert_slot(&mut self, cs: usize, sf: &SignedFrame, now_us: u64, pid: i32, uid: u32, pre_sig: i32, defer: Option<&mut Job>, v: &mut dyn Verifier) -> i32 {
        let sf_pid = sf.frame.pseudo_id;
        if self.certs[cs].pseudo_id != sf_pid {
            return R_PERM;
        }
        // QG-46: later frames under a held certificate (feature fix_vtype_noframe = negative control without this check)
        #[cfg(all(feature = "fix_vtype", not(feature = "fix_vtype_noframe")))]
        if sf.frame.vehicle_type as u32 != self.certs[cs].cert_vtype {
            return R_PERM;
        }
        // cheap checks first (age and replay), the ECDSA verification only for a frame that could be accepted
        let gen = gen_ms_of(sf);
        let age = gen_ms(now_us).wrapping_sub(gen) as i32;
        let fttl = sf.frame.ttl_ms as u32;
        let ttl = (if fttl < DEFAULT_TTL_MS { fttl } else { DEFAULT_TTL_MS }) as i32;
        if age >= ttl || age < -FRAME_MAX_AHEAD_MS {
            return R_TIME;
        }
        if self.certs[cs].have_gen != 0 && (gen.wrapping_sub(self.certs[cs].last_gen_ms) as i32) <= 0 {
            return R_ALREADY;
        }
        let mut pre_sig = pre_sig;
        if pre_sig < 0 {
            if let Some(w) = defer {
                {
                    *w = Job::zero();
                    w.kind = 2;
                    w.j.sf = *sf;
                    w.ca_ok = 1;
                    w.sig_ok = -1;
                    if self.certs[cs].has_key != 0 {
                        w.has_key = 1;
                        w.key = self.certs[cs].pubkey;
                    }
                    return R_NEED_VERIFY;
                }
            }
            let key = self.certs[cs].pubkey;
            let fsig = sf.sig;
            pre_sig = if self.certs[cs].has_key != 0 && crate::sig_s_allowed(&fsig) && v.frame_verify(&key, sf) { 1 } else { 0 };
        }
        if pre_sig != 1 {
            return R_PERM;
        }
        self.certs[cs].last_gen_ms = gen; // consumed once the signature is valid, even if the frame is then refused
        self.certs[cs].have_gen = 1;
        self.certs[cs].proven = 1;
        self.certs[cs].last_ok_us = now_us; // the car is alive: it stays a member
        let rc = self.cache_upsert(&sf.frame, now_us, pid, uid, false);
        if rc == R_OK {
            self.certs[cs].last_frame = sf.frame;
            self.certs[cs].have_frame = 1;
            // the frame lives for its TTL from when it was generated, not from receipt
            let left = (ttl - if age > 0 { age } else { 0 }) as u64 * 1000;
            for i in 0..MAX_ACTIVE_NODES {
                let sid = self.cache[i].frame.pseudo_id;
                if self.cache[i].in_use != 0 && sid == sf_pid {
                    self.cache[i].expires_at_us = now_us.wrapping_add(left);
                }
            }
        }
        rc
    }

    /// C `v2v_join_prepare`.
    pub fn join_prepare(&mut self, j: &Join, now_us: u64, pid: i32, uid: u32, w: &mut Job, v: &mut dyn Verifier) -> i32 {
        w.has_key = 0;
        self.cert_join_core(j, now_us, pid, uid, None, Some(w), v)
    }

    /// C `v2v_frame_prepare`.
    pub fn frame_prepare(&mut self, sf: &SignedFrame, now_us: u64, pid: i32, uid: u32, w: &mut Job, v: &mut dyn Verifier) -> i32 {
        w.has_key = 0;
        self.signed_upsert_any(sf, now_us, pid, uid, -1, Some(w), v)
    }

    /// C `v2v_verify_commit`.
    pub fn verify_commit(&mut self, w: &mut Job, now_us: u64, pid: i32, uid: u32, v: &mut dyn Verifier) -> i32 {
        if w.kind == 1 {
            let j = w.j;
            return self.cert_join_core(&j, now_us, pid, uid, Some(w), None, v);
        }
        let sf = w.j.sf;
        let pre = if w.sig_ok == 1 { 1 } else { 0 };
        self.signed_upsert_any(&sf, now_us, pid, uid, pre, None, v)
    }

    /// C `v2v_members_active`: pseudo-IDs of members that are proven and not silent, ascending; at most `out.len()`.
    pub fn members_active(&self, now_us: u64, out: &mut [u32]) -> i32 {
        let max = out.len();
        let mut n = 0usize;
        for i in 0..CERT_SLOTS {
            if self.certs[i].in_use != 0 && self.certs[i].proven != 0 && !self.member_silent(i, now_us) && n < max {
                out[n] = self.certs[i].pseudo_id;
                n += 1;
            }
        }
        for i in 1..n {
            let mut k = i;
            while k > 0 && out[k - 1] > out[k] {
                out.swap(k, k - 1);
                k -= 1;
            }
        }
        n as i32
    }

    /// C `v2v_members_silent`.
    pub fn members_silent(&self, now_us: u64) -> i32 {
        let mut n = 0;
        for i in 0..CERT_SLOTS {
            if self.member_silent(i, now_us) {
                n += 1;
            }
        }
        n
    }

    /// C `v2v_cert_sweep` (without the print): release certificates whose validity has ended.
    pub fn cert_sweep(&mut self, now_s: u32) -> u32 {
        let mut released = 0;
        for i in 0..CERT_SLOTS {
            if self.certs[i].in_use != 0 && now_s >= self.certs[i].not_after_s {
                wipe_cert(&mut self.certs[i]);
                released += 1;
            }
        }
        released
    }

    /// C `v2v_cert_reset`.
    pub fn cert_reset(&mut self) {
        for s in self.certs.iter_mut() {
            wipe_cert(s);
        }
        self.unknown_id = [0; UNKNOWN_SLOTS];
        self.unknown_us = [0; UNKNOWN_SLOTS];
        self.ca_ok = [[0; 8]; CA_OK_SLOTS];
        self.ca_ok_next = 0;
    }
}

impl Default for Device {
    fn default() -> Self {
        Device::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Mock {
        ca_good: bool,
        sig_good: bool,
        usable: bool,
        calls: u32,
    }
    impl Verifier for Mock {
        fn ca_verify(&mut self, _c: &Cert) -> bool {
            self.calls += 1;
            self.ca_good
        }
        fn key_usable(&mut self, _p: &[u8; 65]) -> bool {
            self.usable
        }
        fn frame_verify(&mut self, _p: &[u8; 65], _sf: &SignedFrame) -> bool {
            self.calls += 1;
            self.sig_good
        }
    }

    fn frame(id: u32, t_ms: u16, s: i16) -> Frame {
        let mut f = Frame { magic: 0x5158, protocol_ver: 5, seg_id: 7, pseudo_id: id, ttl_ms: 300, t_ms, s_cm: s, d_cm: 0, len_dm: 40, wid_dm: 18, ..Frame::default() };
        f.crc16 = crate::crc16(&f);
        f
    }

    #[test]
    fn cache_ttl_and_sweep() {
        let mut d = Device::new();
        let f = frame(0xA100, 10, 0);
        assert_eq!(d.cache_upsert(&f, 1_000_000, 0, 0, true), R_OK);
        assert_eq!(d.cache_upsert(&f, 1_100_000, 0, 0, true), R_ALREADY); // same t_ms: not newer
        assert_eq!(d.cache_sweep(1_299_999), 0);
        assert_eq!(d.cache_sweep(1_300_000), 1); // expires exactly at now + 300 ms
        assert_eq!(d.cache[0].in_use, 0);
        assert_eq!(d.total_evicted, 1);
        assert_eq!(d.last_evict_lateness_us, 0);
    }

    #[test]
    fn cache_refuses_a_jump_and_a_second_owner() {
        let mut d = Device::new();
        assert_eq!(d.cache_upsert(&frame(1, 10, 0), 0, 5, 5, true), R_OK);
        assert_eq!(d.cache_upsert(&frame(1, 20, 1000), 10_000, 5, 5, true), R_DOM); // 1000 cm in 10 ms
        assert_eq!(d.cache_upsert(&frame(1, 20, 5), 10_000, 6, 5, true), R_PERM); // another sender
        assert_eq!(d.cache_upsert(&frame(1, 20, 5), 10_000, 5, 5, true), R_OK);
    }

    #[test]
    fn join_without_ca_key_is_refused_before_anything_is_kept() {
        let mut d = Device::new();
        let mut j = Join::zero();
        j.cert.magic = CERT_MAGIC;
        j.cert.version = CERT_VERSION;
        j.cert.pseudo_id = 0xB200;
        j.cert.not_before_s = 0;
        j.cert.not_after_s = 100;
        j.sf.cert_digest = cert_digest(&j.cert);
        j.sf.frame = frame(0xB200, 5000, 0);
        j.sf.seq = 0;
        let mut m = Mock { ca_good: true, sig_good: true, usable: true, calls: 0 };
        assert_eq!(d.cert_join(&j, 5_000_000, 0, 0, &mut m), R_PERM); // ca_pub = 0: no CA key, so the issuer signature counts as bad
        assert_eq!(m.calls, 0);
        assert!(d.certs.iter().all(|c| c.in_use == 0));
        d.ca_pub = 1;
        assert_eq!(d.cert_join(&j, 5_000_000, 0, 0, &mut m), R_OK);
        assert_eq!(m.calls, 2);
        assert_eq!(d.members_active(5_000_000, &mut [0u32; 4]), 1);
    }

    /// QG-46: a join and a later signed frame claiming another vehicle_type than the certificate (2 = ordinary car, frame says 1 = two-ended).
    /// Default: both accepted (the finding). Feature fix_vtype: both refused with R_PERM before any signature work, the cache keeps the
    /// certificate's type; fix_vtype_noframe (negative control) refuses the join but accepts the later frame.
    #[test]
    fn vehicle_type_bound_to_certificate() {
        let mk = |vt: u8, t_ms: u16| {
            let mut f = frame(0xB200, t_ms, 0);
            f.vehicle_type = vt;
            f.crc16 = crate::crc16(&f);
            f
        };
        let mut d = Device::new();
        d.ca_pub = 1;
        let mut j = Join::zero();
        j.cert.magic = CERT_MAGIC;
        j.cert.version = CERT_VERSION;
        j.cert.vehicle_type = 2;
        j.cert.pseudo_id = 0xB200;
        j.cert.not_before_s = 0;
        j.cert.not_after_s = 100;
        j.sf.cert_digest = cert_digest(&j.cert);
        j.sf.frame = mk(1, 5000);
        let mut m = Mock { ca_good: true, sig_good: true, usable: true, calls: 0 };
        let mismatch_join = d.cert_join(&j, 5_000_000, 0, 0, &mut m);
        if cfg!(feature = "fix_vtype") {
            assert_eq!(mismatch_join, R_PERM);
            assert_eq!(m.calls, 0);
            assert!(d.certs.iter().all(|c| c.in_use == 0) && d.cache.iter().all(|c| c.in_use == 0));
            j.sf.frame = mk(2, 5000);
            assert_eq!(d.cert_join(&j, 5_000_000, 0, 0, &mut m), R_OK); // matching type accepted
        } else {
            assert_eq!(mismatch_join, R_OK);
            assert_eq!(d.cache[0].frame.vehicle_type, 1);
        }
        let mut sf = j.sf;
        sf.frame = mk(1, 5040);
        let calls = m.calls;
        let later = d.signed_upsert(&sf, 5_040_000, 0, 0, &mut m);
        if cfg!(all(feature = "fix_vtype", not(feature = "fix_vtype_noframe"))) {
            assert_eq!(later, R_PERM);
            assert_eq!(m.calls, calls);
            assert_eq!(d.cache[0].frame.vehicle_type, 2);
        } else {
            assert_eq!(later, R_OK);
            assert_eq!(d.cache[0].frame.vehicle_type, 1);
        }
        sf.frame = mk(2, 5080);
        assert_eq!(d.signed_upsert(&sf, 5_080_000, 0, 0, &mut m), R_OK); // matching later frame accepted in every build
    }
}
