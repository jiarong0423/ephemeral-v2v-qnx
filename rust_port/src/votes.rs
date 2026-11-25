//! Stage 3, block 2 of the Rust track: the votes (`qnx_target/src/v2v_ttl_resmgr.c`, lines 871-1075): the digests a car votes, the device's
//! relay of the votes (`v2v_vote_post`, `v2v_vote_fill_report_at`, `live_frame_of`), the faulty-voter check (`v2v_agree_dissenters`) and a receiver's own
//! signature check (`v2v_vote_sig_ok`). The commit rule itself (`v2v_agree_decide`, `vote_same_content`) was ported in stage 1 (`lib.rs`).
//!
//! The state C keeps in `g_votes` and `g_vote_round` is one explicit value (`Votes`); the certificate table and the frame cache it reads (and the `voted`
//! flag it sets) are the stage 2 `Device`. The ECDSA verification stays C (OpenSSL): the logic asks a `VoteVerifier`. Not ported: `v2v_vote_make(_chain)`
//! (signing, an OpenSSL call), `v2v_vote_fill_report` (takes the clock from the system: the port takes the time as an argument, like `_at`).
//! Written for Rust 1.85: edition 2021, no dependencies, safe code only.
use crate::planner::sha256;
use crate::state::{Cert, Device, CERT_SLOTS};
use crate::{vote_same_content, Frame, Vote, MAX_ACTIVE_NODES, VOTE_MAGIC, VOTE_VERSION};

pub const VOTE_ROUNDS_PER_S: u32 = 16;
pub const RELAY_VOTES: usize = 6;
/// the largest frame count `input_digest` handles (a fixed buffer, no allocation); the device has at most `MAX_ACTIVE_NODES` frames
pub const DIGEST_MAX_FRAMES: usize = 32;

// ---- result codes of `post`: C returns 0 or a negative errno (numbers differ between platforms), the port neutral codes ----
pub const V_OK: i32 = 0;
pub const V_INVAL: i32 = 1; // C -EINVAL
pub const V_ACCES: i32 = 2; // C -EACCES: no valid, proven certificate
pub const V_PERM: i32 = 3; // C -EPERM: wrong ID or bad signature
pub const V_RANGE: i32 = 4; // C -ERANGE: round too far from the trust clock
pub const V_SRCH: i32 = 5; // C -ESRCH: no live frame (not taking part)
pub const V_STALE: i32 = 6; // C -ESTALE: older round than this car's last vote
pub const V_ALREADY: i32 = 7; // C -EALREADY: the same vote again (replay) or a different one in the same round
pub const V_NOSPC: i32 = 8; // C -ENOSPC

/// The signature fact the vote logic needs; C answers it with OpenSSL.
pub trait VoteVerifier {
    /// C: the key made from `pubkey` is usable (`v2v_key_from_pub` not NULL) and `v2v_verify_raw(key, v, offsetof(sig), v->sig)` is true.
    fn vote_verify(&mut self, pubkey: &[u8; 65], v: &Vote) -> bool;
}

impl Vote {
    pub const fn zero() -> Vote {
        Vote { magic: 0, version: 0, n_inputs: 0, pseudo_id: 0, round: 0, plan_hash: 0, input_digest: [0; 8], cert_digest: [0; 8], seq: 0, chain: [0; 8], sig: [0; 64] }
    }
    /// The 106 wire bytes (little-endian fields).
    pub fn to_bytes(&self) -> [u8; 106] {
        let mut b = [0u8; 106];
        let (magic, pid, round, ph, seq) = (self.magic, self.pseudo_id, self.round, self.plan_hash, self.seq);
        b[0..2].copy_from_slice(&magic.to_le_bytes());
        b[2] = self.version;
        b[3] = self.n_inputs;
        b[4..8].copy_from_slice(&pid.to_le_bytes());
        b[8..12].copy_from_slice(&round.to_le_bytes());
        b[12..16].copy_from_slice(&ph.to_le_bytes());
        let (idg, cdg, ch, sg) = (self.input_digest, self.cert_digest, self.chain, self.sig);
        b[16..24].copy_from_slice(&idg);
        b[24..32].copy_from_slice(&cdg);
        b[32..34].copy_from_slice(&seq.to_le_bytes());
        b[34..42].copy_from_slice(&ch);
        b[42..106].copy_from_slice(&sg);
        b
    }
}

/// C `v2v_input_digest`: digest of the frames a decision was computed from: the last 8 bytes of SHA-256 over the frame bytes. All zero for no frames.
/// More than `DIGEST_MAX_FRAMES` frames are not supported (C hashes any number): the result is all zero then (the caller has at most 16).
pub fn input_digest(fr: &[Frame]) -> [u8; 8] {
    let mut out = [0u8; 8];
    if fr.is_empty() || fr.len() > DIGEST_MAX_FRAMES {
        return out;
    }
    let mut buf = [0u8; 56 * DIGEST_MAX_FRAMES];
    for (i, f) in fr.iter().enumerate() {
        buf[56 * i..56 * i + 56].copy_from_slice(&f.to_bytes());
    }
    let h = sha256(&buf[..56 * fr.len()]);
    out.copy_from_slice(&h[24..32]);
    out
}

/// C `v2v_member_digest`: bind the member set into the digest a car votes. `ids` need not be sorted; more than 16 are cut to 16 (the first 16).
pub fn member_digest(frames_digest: &[u8; 8], ids: &[u32]) -> [u8; 8] {
    let n = ids.len().min(MAX_ACTIVE_NODES);
    let mut sorted = [0u32; MAX_ACTIVE_NODES];
    sorted[..n].copy_from_slice(&ids[..n]);
    for i in 1..n {
        let mut j = i;
        while j > 0 && sorted[j - 1] > sorted[j] {
            sorted.swap(j, j - 1);
            j -= 1;
        }
    }
    // C builds a uint32 buffer: the 8 digest bytes as two words, then the sorted ids (little-endian on the QNX targets and the build hosts)
    let mut buf = [0u8; 4 * (2 + MAX_ACTIVE_NODES)];
    buf[..8].copy_from_slice(frames_digest);
    for (i, id) in sorted[..n].iter().enumerate() {
        buf[8 + 4 * i..12 + 4 * i].copy_from_slice(&id.to_le_bytes());
    }
    let h = sha256(&buf[..4 * (2 + n)]);
    let mut out = [0u8; 8];
    out.copy_from_slice(&h[24..32]);
    out
}

/// C `v2v_vote_sig_ok`: a receiver's own check: the vote is signed under the certificate it holds for that pseudo-ID (the first certificate with that ID).
pub fn vote_sig_ok(v: &Vote, certs: &[Cert], ver: &mut dyn VoteVerifier) -> bool {
    if v.magic != VOTE_MAGIC || v.version != VOTE_VERSION {
        return false;
    }
    let vid = v.pseudo_id;
    for c in certs {
        let cid = c.pseudo_id;
        if cid != vid {
            continue;
        }
        let d = crate::state::cert_digest(c);
        if d != v.cert_digest {
            return false;
        }
        let pk = c.pubkey;
        let vsig = v.sig;
        return crate::sig_s_allowed(&vsig) && ver.vote_verify(&pk, v);
    }
    false
}

/// C `v2v_agree_dissenters`: votes of this round from OTHER cars that have the same frame/member digest and frame count as `mine` but another plan hash.
/// Returns how many; `ids` gets the first `ids.len()` (C's `max`).
pub fn agree_dissenters(mine: &Vote, votes: &[Vote], ids: &mut [u32]) -> i32 {
    let mut k: i32 = 0;
    let (mr, mid, mph) = (mine.round, mine.pseudo_id, mine.plan_hash);
    for v in votes {
        let (vr, vid, vph) = (v.round, v.pseudo_id, v.plan_hash);
        if vr != mr || vid == mid {
            continue;
        }
        if v.n_inputs == mine.n_inputs && v.input_digest == mine.input_digest && vph != mph {
            if (k as usize) < ids.len() {
                ids[k as usize] = vid;
            }
            k += 1;
        }
    }
    k
}

/// C `vote_slot_t`
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VoteSlot {
    pub in_use: i32,
    pub conflict: i32,
    pub v: Vote,
    /// C `V2V_FIX_EQUIV`: the car's second, different, validly signed vote of the slot's round (the proof of equivocation the report shows)
    #[cfg(feature = "fix_equiv")]
    pub proof: Vote,
}

impl VoteSlot {
    pub const fn zero() -> VoteSlot {
        VoteSlot {
            in_use: 0,
            conflict: 0,
            v: Vote::zero(),
            #[cfg(feature = "fix_equiv")]
            proof: Vote::zero(),
        }
    }
}

/// The votes of one report: C writes these fields of `v2v_arbitration_report_t` in `v2v_vote_fill_report_at` (the others are not touched by it).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VoteReport {
    pub votes: [Vote; RELAY_VOTES],
    pub vote_round: u32,
    pub vote_count: u8,
    pub vote_conflict: u8,
    pub unknown_certs: u8,
    pub silent_members: u8,
}

impl VoteReport {
    pub const fn zero() -> VoteReport {
        VoteReport { votes: [Vote::zero(); RELAY_VOTES], vote_round: 0, vote_count: 0, vote_conflict: 0, unknown_certs: 0, silent_members: 0 }
    }
}

/// C `V2V_EVIDENCE_SLOTS` (J11 black box)
#[cfg(feature = "fix_equiv_bb")]
pub const EVIDENCE_SLOTS: usize = 16;

/// C `v2v_evidence_t` (J11, feature `fix_equiv_bb`): two different, validly signed votes of one car for one round, as received
#[cfg(feature = "fix_equiv_bb")]
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Evidence {
    pub seq: u32,
    pub pseudo_id: u32,
    pub round: u32,
    pub recorded_us: u64,
    pub first: Vote,
    pub second: Vote,
}
#[cfg(feature = "fix_equiv_bb")]
const _: () = assert!(core::mem::size_of::<Evidence>() == 232);

/// C `v2v_evidence_ring_t`: the append-only black box (the oldest entry is overwritten when full; `appended` keeps counting)
#[cfg(feature = "fix_equiv_bb")]
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct EvidenceRing {
    pub appended: u32,
    pub count: u32,
    pub e: [Evidence; EVIDENCE_SLOTS],
}
#[cfg(feature = "fix_equiv_bb")]
const _: () = assert!(core::mem::size_of::<EvidenceRing>() == 3720);

#[cfg(feature = "fix_equiv_bb")]
impl EvidenceRing {
    pub const fn zero() -> EvidenceRing {
        const Z: Evidence = Evidence { seq: 0, pseudo_id: 0, round: 0, recorded_us: 0, first: Vote::zero(), second: Vote::zero() };
        EvidenceRing { appended: 0, count: 0, e: [Z; EVIDENCE_SLOTS] }
    }
    /// C `evid_has`: an entry for this car and round is in the ring
    pub fn has(&self, id: u32, round: u32) -> bool {
        let count = self.count;
        let mut i = 0usize;
        while (i as u32) < count && i < EVIDENCE_SLOTS {
            let (eid, er) = (self.e[i].pseudo_id, self.e[i].round);
            if eid == id && er == round {
                return true;
            }
            i += 1;
        }
        false
    }
    /// C `evid_append`
    pub fn append(&mut self, first: &Vote, second: &Vote, now_us: u64) {
        let seq = self.appended.wrapping_add(1);
        let idx = (seq.wrapping_sub(1) as usize) % EVIDENCE_SLOTS;
        self.e[idx] = Evidence { seq, pseudo_id: second.pseudo_id, round: second.round, recorded_us: now_us, first: *first, second: *second };
        self.appended = seq;
        let c = self.count;
        if (c as usize) < EVIDENCE_SLOTS {
            self.count = c + 1;
        }
    }
}

/// C `g_votes` and `g_vote_round` (and, with `fix_equiv_bb`, the black box `g_evid`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Votes {
    pub slots: [VoteSlot; MAX_ACTIVE_NODES],
    pub round: u32,
    #[cfg(feature = "fix_equiv_bb")]
    pub evid: EvidenceRing,
}

/// C `live_frame_of`: the car has a frame in the cache that has not expired.
fn live_frame_of(dev: &Device, id: u32, now_us: u64) -> bool {
    for i in 0..MAX_ACTIVE_NODES {
        let fid = dev.cache[i].frame.pseudo_id;
        if dev.cache[i].in_use != 0 && now_us < dev.cache[i].expires_at_us && fid == id {
            return true;
        }
    }
    false
}

fn vote_eq(a: &Vote, b: &Vote) -> bool {
    a.to_bytes() == b.to_bytes()
}

impl Votes {
    pub const fn new() -> Votes {
        Votes {
            slots: [VoteSlot::zero(); MAX_ACTIVE_NODES],
            round: 0,
            #[cfg(feature = "fix_equiv_bb")]
            evid: EvidenceRing::zero(),
        }
    }

    /// C `v2v_vote_reset`
    pub fn reset(&mut self) {
        *self = Votes::new();
    }

    /// C `v2v_vote_post`: the device as relay. One slot per car: its newest vote (the first one of its round). Only a car that is taking part (a live
    /// signed frame under a proven certificate) may vote. Sets the `voted` flag of the car's certificate (P5), hence `dev` is mutable.
    pub fn post(&mut self, dev: &mut Device, v: &Vote, now_us: u64, ver: &mut dyn VoteVerifier) -> i32 {
        if v.magic != VOTE_MAGIC || v.version != VOTE_VERSION || v.n_inputs == 0 {
            return V_INVAL;
        }
        let now_s = (now_us / 1_000_000) as u32;
        let mut cs: Option<usize> = None;
        for i in 0..CERT_SLOTS {
            if dev.certs[i].in_use != 0 && dev.certs[i].digest == v.cert_digest {
                cs = Some(i);
                break;
            }
        }
        let cs = match cs {
            Some(c) if now_s < dev.certs[c].not_after_s && dev.certs[c].proven != 0 => c,
            _ => return V_ACCES,
        };
        let vid = v.pseudo_id;
        if dev.certs[cs].pseudo_id != vid {
            return V_PERM;
        }
        // rounds follow the trust clock (16 per second): a round far from the receiver's clock is refused
        let lo: u32 = if now_s > 2 { (now_s - 2).wrapping_mul(VOTE_ROUNDS_PER_S) } else { 0 };
        let hi: u32 = now_s.wrapping_add(3).wrapping_mul(VOTE_ROUNDS_PER_S);
        let vr = v.round;
        if vr < lo || vr >= hi {
            return V_RANGE;
        }
        if !live_frame_of(dev, vid, now_us) {
            return V_SRCH;
        }
        let mut slot: i32 = -1;
        let mut free_slot: i32 = -1;
        for i in 0..MAX_ACTIVE_NODES {
            let sid = self.slots[i].v.pseudo_id;
            if self.slots[i].in_use != 0 && sid == vid {
                slot = i as i32;
            } else if free_slot < 0 && (self.slots[i].in_use == 0 || !live_frame_of(dev, sid, now_us)) {
                // free: never used, or held by a car that is no longer taking part (no live frame)
                free_slot = i as i32;
            }
        }
        if slot >= 0 {
            let sr = self.slots[slot as usize].v.round;
            if vr < sr {
                return V_STALE;
            }
            if vr == sr && vote_eq(&self.slots[slot as usize].v, v) {
                return V_ALREADY;
            }
            // C V2V_FIX_EQUIV: the proof again (re-broadcast by several cars) is refused before the signature work
            #[cfg(feature = "fix_equiv")]
            if vr == sr && self.slots[slot as usize].conflict != 0 && vote_eq(&self.slots[slot as usize].proof, v) {
                return V_ALREADY;
            }
            // C V2V_FIX_EQUIV_BB (J11): the car is already in the black box for this round: a further different vote is refused before the signature work
            #[cfg(feature = "fix_equiv_bb")]
            if vr == sr && !vote_same_content(&self.slots[slot as usize].v, v) && self.evid.has(vid, vr) {
                return V_ALREADY;
            }
        }
        let verified = dev.certs[cs].has_key != 0 && {
            let pk = dev.certs[cs].pubkey;
            let vsig = v.sig;
            crate::sig_s_allowed(&vsig) && ver.vote_verify(&pk, v)
        };
        if !verified {
            return V_PERM;
        }
        dev.certs[cs].voted = 1; // from now on this member is not dropped as an obstacle for the freeze time (P5)
        if slot >= 0 && vr == self.slots[slot as usize].v.round {
            // the first vote of a round is the one that counts: a later, different vote of the same car in the same round is refused (not a conflict)
            if !vote_same_content(&self.slots[slot as usize].v, v) {
                // C V2V_FIX_EQUIV: both votes verified under the car's key: proof that the car equivocated in this round; the slot is marked
                // (the report's vote_conflict holds every car that reads this device) and the first proof is kept for the report
                #[cfg(feature = "fix_equiv")]
                if self.slots[slot as usize].conflict == 0 {
                    self.slots[slot as usize].conflict = 1;
                    self.slots[slot as usize].proof = *v;
                }
                // C V2V_FIX_EQUIV_BB (J11): both votes verified under the car's key: the pair goes into the black box; the first keeps counting,
                // no conflict mark (nobody is made to hold), nobody has to re-broadcast
                #[cfg(feature = "fix_equiv_bb")]
                {
                    let first = self.slots[slot as usize].v;
                    self.evid.append(&first, v, now_us);
                }
                return V_ALREADY;
            }
            return V_OK;
        }
        if slot < 0 {
            if free_slot < 0 {
                return V_NOSPC;
            }
            slot = free_slot;
        }
        let s = &mut self.slots[slot as usize];
        s.in_use = 1;
        s.conflict = 0;
        s.v = *v;
        #[cfg(feature = "fix_equiv")]
        {
            s.proof = Vote::zero(); // a proof belongs to its round
        }
        if vr > self.round {
            self.round = vr;
        }
        V_OK
    }

    /// C `v2v_vote_fill_report_at`: relays the votes of the cars taking part now (live frame), sorted by pseudo-ID, at most `RELAY_VOTES`; `vote_count`
    /// is the number of such cars; `vote_conflict` = one of them sent two different votes for its round.
    pub fn fill_report_at(&self, dev: &Device, now_us: u64) -> VoteReport {
        let mut idx = [0usize; MAX_ACTIVE_NODES];
        let mut n = 0usize;
        let mut conflict = 0u8;
        for i in 0..MAX_ACTIVE_NODES {
            let sid = self.slots[i].v.pseudo_id;
            if self.slots[i].in_use != 0 && live_frame_of(dev, sid, now_us) {
                idx[n] = i;
                n += 1;
            }
        }
        for i in 1..n {
            let mut j = i;
            while j > 0 && self.slots[idx[j - 1]].v.pseudo_id > self.slots[idx[j]].v.pseudo_id {
                idx.swap(j, j - 1);
                j -= 1;
            }
        }
        let mut rep = VoteReport::zero();
        for k in 0..n {
            let s = &self.slots[idx[k]];
            if s.conflict != 0 {
                conflict = 1;
            }
            let r = s.v.round;
            if r > rep.vote_round {
                rep.vote_round = r;
            }
            if k < RELAY_VOTES {
                rep.votes[k] = s.v;
            }
        }
        // C V2V_FIX_EQUIV: the proofs follow the cars' votes in the free places (same order) and are counted in vote_count
        #[cfg(feature = "fix_equiv")]
        {
            let shown = n.min(RELAY_VOTES);
            let mut extra = 0usize;
            for k in 0..n {
                let s = &self.slots[idx[k]];
                let pm = s.proof.magic;
                if s.conflict != 0 && pm == VOTE_MAGIC && shown + extra < RELAY_VOTES {
                    rep.votes[shown + extra] = s.proof;
                    extra += 1;
                }
            }
            n += extra;
        }
        rep.vote_count = n as u8;
        rep.vote_conflict = conflict;
        rep.unknown_certs = dev.unknown_recent(now_us) as u8;
        rep.silent_members = dev.members_silent(now_us) as u8;
        rep
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn member_digest_ignores_the_order_of_the_ids() {
        let d = [1u8, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(member_digest(&d, &[5, 3, 9]), member_digest(&d, &[9, 5, 3]));
        assert_ne!(member_digest(&d, &[5, 3, 9]), member_digest(&d, &[5, 3]));
    }

    #[test]
    fn empty_frame_list_digest_is_zero() {
        assert_eq!(input_digest(&[]), [0u8; 8]);
    }
}
