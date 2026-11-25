//! J11 (owner decision H, feature `fix_equiv_bb`): the ordered path. Port of the C `V2V_FIX_EQUIV_BB` block of `qnx_target/src/v2v_ttl_resmgr.c`
//! (`v2v_path_begin`, `v2v_path_step_done`, `step_sig_ok`, `v2v_path_may_move`). A car that committed to a plan carries out its step k only after it
//! accepted the signed "step done" of step k-1 from that step's owner; step 0 starts at once; no progress for 1.5 s while waiting: hold and log help.
//! The ECDSA check stays C (OpenSSL), asked through `StepVerifier`; the low-s rule (feature `low_s`) is applied here as in the vote code.
//! Negative controls: `fix_equiv_bb_nogate` (no predecessor check), `fix_equiv_bb_nohash` (the plan hash of a step done is not compared).
//! Checked bit for bit against C by `rust_port/tests/diff_harness_path.c`. Safe code only.
use crate::state::{cert_digest, Cert};

pub const STEP_MAGIC: u16 = 0x4453;
pub const STEP_VERSION: u8 = 1;
pub const PATH_MAX_STEPS: usize = 18;
pub const PATH_HELP_MS: u64 = 1500;
pub const PATH_HOLD: i32 = 0;
pub const PATH_GO: i32 = 1;
pub const PATH_HELP: i32 = 2;
// result codes of `step_done` (C: 0 or a negative errno; the port neutral codes, mapped back by C rs_path_errno)
pub const P_OK: i32 = 0;
pub const P_INVAL: i32 = 1; // C -EINVAL: not a step done (magic, version)
pub const P_NOENT: i32 = 2; // C -ENOENT: no committed plan
pub const P_STALE: i32 = 3; // C -ESTALE: another round (replay)
pub const P_BADMSG: i32 = 4; // C -EBADMSG: another plan hash
pub const P_RANGE: i32 = 5; // C -ERANGE: step outside the plan
pub const P_ACCES: i32 = 6; // C -EACCES: the signer does not own that step
pub const P_ALREADY: i32 = 7; // C -EALREADY: that step is done already (replay)
pub const P_PERM: i32 = 8; // C -EPERM: no certificate with that ID and digest, or a bad signature
// errors of `may_move` (C -EINVAL, -EACCES, -EALREADY)
pub const M_INVAL: i32 = -1;
pub const M_ACCES: i32 = -2;
pub const M_ALREADY: i32 = -3;

const GATE: bool = !cfg!(feature = "fix_equiv_bb_nogate");
const HASHCHK: bool = !cfg!(feature = "fix_equiv_bb_nohash");

/// C `v2v_step_done_t` (88 wire bytes)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct StepDone {
    pub magic: u16,
    pub version: u8,
    pub step: u8,
    pub pseudo_id: u32,
    pub round: u32,
    pub plan_hash: u32,
    pub cert_digest: [u8; 8],
    pub sig: [u8; 64],
}
const _: () = assert!(core::mem::size_of::<StepDone>() == 88);

/// C `v2v_path_t`
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Path {
    pub active: u32,
    pub self_id: u32,
    pub round: u32,
    pub plan_hash: u32,
    pub n_steps: u32,
    pub owner: [u32; PATH_MAX_STEPS],
    pub done_mask: u32,
    pub help_logged: u32,
    pub help_count: u32,
    pub refused: u32,
    pub progress_us: u64,
}

/// The signature fact the gate needs; C answers it with OpenSSL (`v2v_verify_ecdsa` under the key made from `pubkey`).
pub trait StepVerifier {
    fn step_verify(&mut self, pubkey: &[u8; 65], sd: &StepDone) -> bool;
}

/// C `step_sig_ok`: the signer's certificate (the first with its pseudo-ID) has the digest the message names and its key verifies the signature
pub fn step_sig_ok(sd: &StepDone, certs: &[Cert], ver: &mut dyn StepVerifier) -> bool {
    let sid = sd.pseudo_id;
    for c in certs {
        let cid = c.pseudo_id;
        if cid != sid {
            continue;
        }
        if cert_digest(c) != sd.cert_digest {
            return false;
        }
        let pk = c.pubkey;
        let sg = sd.sig;
        return crate::sig_s_allowed(&sg) && ver.step_verify(&pk, sd);
    }
    false
}

impl Path {
    pub const fn zero() -> Path {
        Path { active: 0, self_id: 0, round: 0, plan_hash: 0, n_steps: 0, owner: [0; PATH_MAX_STEPS], done_mask: 0, help_logged: 0, help_count: 0, refused: 0, progress_us: 0 }
    }

    /// C `v2v_path_begin`: 0, or `P_INVAL` (too many steps; the path stays inactive)
    pub fn begin(&mut self, self_id: u32, round: u32, plan_hash: u32, owners: &[u32], now_us: u64) -> i32 {
        *self = Path::zero();
        if owners.len() > PATH_MAX_STEPS {
            return P_INVAL;
        }
        self.active = 1;
        self.self_id = self_id;
        self.round = round;
        self.plan_hash = plan_hash;
        self.n_steps = owners.len() as u32;
        self.owner[..owners.len()].copy_from_slice(owners);
        self.progress_us = now_us;
        0
    }

    /// C `v2v_path_step_done`: cheap checks first, then the signature
    pub fn step_done(&mut self, sd: &StepDone, certs: &[Cert], now_us: u64, ver: &mut dyn StepVerifier) -> i32 {
        let (magic, step, sid, sr, sh) = (sd.magic, sd.step as u32, sd.pseudo_id, sd.round, sd.plan_hash);
        let r = if magic != STEP_MAGIC || sd.version != STEP_VERSION {
            P_INVAL
        } else if self.active == 0 {
            P_NOENT
        } else if sr != self.round {
            P_STALE
        } else if HASHCHK && sh != self.plan_hash {
            P_BADMSG
        } else if step >= self.n_steps {
            P_RANGE
        } else if sid != self.owner[step as usize] {
            P_ACCES
        } else if self.done_mask & (1u32 << step) != 0 {
            P_ALREADY
        } else if step_sig_ok(sd, certs, ver) {
            P_OK
        } else {
            P_PERM
        };
        if r == P_OK {
            self.done_mask |= 1u32 << step;
            self.progress_us = now_us;
            self.help_logged = 0;
        } else if self.active != 0 {
            self.refused = self.refused.wrapping_add(1);
        }
        r
    }

    /// C `v2v_path_may_move`: `PATH_GO`, `PATH_HOLD`, `PATH_HELP`, or `M_INVAL` / `M_ACCES` / `M_ALREADY`
    pub fn may_move(&mut self, k: i32, now_us: u64) -> i32 {
        if self.active == 0 || k < 0 || k as u32 >= self.n_steps {
            return M_INVAL;
        }
        let ku = k as usize;
        if self.owner[ku] != self.self_id {
            return M_ACCES;
        }
        if self.done_mask & (1u32 << ku) != 0 {
            return M_ALREADY;
        }
        if k == 0 || !GATE || self.done_mask & (1u32 << (ku - 1)) != 0 {
            return PATH_GO;
        }
        if now_us >= self.progress_us && now_us - self.progress_us >= PATH_HELP_MS * 1000 {
            if self.help_logged == 0 {
                self.help_logged = 1;
                self.help_count = self.help_count.wrapping_add(1);
            }
            return PATH_HELP;
        }
        PATH_HOLD
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Yes;
    impl StepVerifier for Yes {
        fn step_verify(&mut self, _p: &[u8; 65], _s: &StepDone) -> bool {
            true
        }
    }
    #[test]
    fn step_zero_goes_and_later_steps_wait_for_their_predecessor() {
        let mut p = Path::zero();
        assert_eq!(p.begin(7, 100, 0xABCD, &[7, 9, 7], 0), 0);
        assert_eq!(p.may_move(0, 0), PATH_GO);
        assert_eq!(p.may_move(1, 0), M_ACCES);
        let want = if GATE { PATH_HOLD } else { PATH_GO };
        assert_eq!(p.may_move(2, 1_000_000), want);
        if GATE {
            assert_eq!(p.may_move(2, 1_500_000), PATH_HELP);
            assert_eq!(p.help_count, 1);
            assert_eq!(p.may_move(2, 2_000_000), PATH_HELP);
            assert_eq!(p.help_count, 1);
        }
    }
    #[test]
    fn refusals_in_order() {
        let mut p = Path::zero();
        p.begin(7, 100, 0xABCD, &[7, 9], 0);
        let mut sd = StepDone { magic: STEP_MAGIC, version: STEP_VERSION, step: 0, pseudo_id: 7, round: 99, plan_hash: 0xABCD, cert_digest: [0; 8], sig: [0; 64] };
        assert_eq!(p.step_done(&sd, &[], 1, &mut Yes), P_STALE);
        sd.round = 100;
        sd.plan_hash = 1;
        assert_eq!(p.step_done(&sd, &[], 1, &mut Yes), if HASHCHK { P_BADMSG } else { P_PERM });
        sd.plan_hash = 0xABCD;
        sd.step = 2;
        assert_eq!(p.step_done(&sd, &[], 1, &mut Yes), P_RANGE);
        sd.step = 1;
        assert_eq!(p.step_done(&sd, &[], 1, &mut Yes), P_ACCES);
        sd.step = 0;
        assert_eq!(p.step_done(&sd, &[], 1, &mut Yes), P_PERM); // no certificate
    }
}
