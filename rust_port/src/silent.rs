//! Stage 3, block 3 of the Rust track: the silent-member obstacles (`qnx_target/src/v2v_ttl_resmgr.c`, lines 1827-1897): a certified member that has sent
//! no accepted frame for 3 s stays in the world model: its last footprint is drawn into the static-obstacle grid (`v2v_silent_obstacles`), and the cars
//! drawn this way are folded into the digest a car votes (`v2v_fold_obstacles_into_digest`).
//!
//! The certificate table is the stage 2 `Device`; the grids are the stage 1b `Grid` (`stat` is C `g_static`, `obs` is `g_obs`); the small state C keeps in
//! `g_frozen_voted_*` and `g_obst_*` is one value (`ObstacleSet`). The geometry (frame outline, cell centres, point in outline) is the stage 1b code, with
//! the C library's `sqrt` as in C. Not ported: the call from `v2v_run_handshake_arbitration_at` (the decision text and timing stay C).
//! Written for Rust 1.85: edition 2021, no dependencies, safe code only.
use crate::geom::{c_sqrt, cell_centre_of, cell_of, frame_quad, point_in_quad, Grid, GRID_H, GRID_W};
use crate::planner::sha256;
use crate::state::{Device, CERT_SLOTS, MEMBER_SILENT_MS};
use crate::Frame;

/// C `V2V_VOTED_FREEZE_MS`: a member that has voted stays a member (never an obstacle) this long after its last frame
pub const VOTED_FREEZE_MS: u64 = 30000;

/// C `g_frozen_voted_id`, `g_frozen_voted_n`, `g_obst_id`, `g_obst_h`, `g_obst_n` (they keep their values between calls, as the C globals).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ObstacleSet {
    pub frozen_voted_id: u32,
    pub frozen_voted_n: i32,
    pub obst_id: [u32; CERT_SLOTS],
    pub obst_h: [[u8; 8]; CERT_SLOTS],
    pub obst_n: i32,
}

impl ObstacleSet {
    pub const fn new() -> ObstacleSet {
        ObstacleSet { frozen_voted_id: 0, frozen_voted_n: 0, obst_id: [0; CERT_SLOTS], obst_h: [[0; 8]; CERT_SLOTS], obst_n: 0 }
    }
}

/// C `member_silent` (the stage 2 function of the same name is private to `state.rs`; it is one line).
fn member_silent(dev: &Device, i: usize, now_us: u64) -> bool {
    dev.certs[i].in_use != 0 && now_us >= dev.certs[i].last_ok_us.wrapping_add(MEMBER_SILENT_MS * 1000)
}

/// C `v2v_silent_obstacles`: draws the last footprint of every silent, proven member that is not live in `fr` into `grid` (`stat` and `obs`), records the
/// drawn cars in `set`, and returns how many were drawn; `ids` gets the first `ids.len()` of them. A member that has voted is not drawn (P5) for
/// `VOTED_FREEZE_MS` after its last frame: it is counted in `set.frozen_voted_n`.
pub fn silent_obstacles(dev: &Device, grid: &mut Grid, set: &mut ObstacleSet, fr: &[Frame], now_us: u64, ids: &mut [u32]) -> u32 {
    let mut k: u32 = 0;
    set.frozen_voted_n = 0;
    set.obst_n = 0;
    for i in 0..CERT_SLOTS {
        let cs = &dev.certs[i];
        if cs.in_use == 0 || cs.proven == 0 || cs.have_frame == 0 || !member_silent(dev, i, now_us) {
            continue;
        }
        // P5: a member that has voted may have committed and be moving: it is NOT turned into a static obstacle; it stays a member
        if cs.voted != 0 && now_us < cs.last_ok_us.wrapping_add(VOTED_FREEZE_MS * 1000) {
            set.frozen_voted_id = cs.pseudo_id;
            set.frozen_voted_n += 1;
            continue;
        }
        let mut live = false;
        for f in fr {
            let fid = f.pseudo_id;
            live |= fid == cs.pseudo_id;
        }
        if live {
            continue;
        }
        if (set.obst_n as usize) < CERT_SLOTS {
            let h = sha256(&cs.last_frame.to_bytes());
            let n = set.obst_n as usize;
            set.obst_id[n] = cs.pseudo_id;
            set.obst_h[n].copy_from_slice(&h[24..32]);
            set.obst_n += 1;
        }
        let q = frame_quad(&cs.last_frame);
        for gy in 0..GRID_H {
            for gx in 0..GRID_W {
                let c = cell_centre_of(gx as i32, gy as i32);
                if point_in_quad(c, &q) {
                    grid.stat[gy][gx] = 1;
                    grid.obs[gy][gx] = 1;
                }
            }
        }
        for e in 0..4 {
            let a = q.v[e];
            let b = q.v[(e + 1) & 3];
            let len = c_sqrt((b.x - a.x) * (b.x - a.x) + (b.y - a.y) * (b.y - a.y));
            let steps = (len / 5.0) as i32 + 1;
            for t in 0..=steps {
                let u = t as f64 / steps as f64;
                if let Some((gx, gy)) = cell_of(a.x + (b.x - a.x) * u, a.y + (b.y - a.y) * u) {
                    grid.stat[gy][gx] = 1;
                    grid.obs[gy][gx] = 1;
                }
            }
        }
        if (k as usize) < ids.len() {
            ids[k as usize] = cs.pseudo_id;
        }
        k += 1;
    }
    k
}

/// C `v2v_fold_obstacles_into_digest`: the cars drawn as obstacles go into the digest a car votes, sorted by pseudo-ID, so that two honest cars with the same
/// digest compute the same plan hash. Without obstacles the digest is unchanged.
pub fn fold_obstacles_into_digest(set: &ObstacleSet, digest: &mut [u8; 8]) {
    if set.obst_n <= 0 {
        return;
    }
    let n = (set.obst_n as usize).min(CERT_SLOTS);
    let mut order = [0usize; CERT_SLOTS];
    for (i, o) in order.iter_mut().enumerate().take(n) {
        *o = i;
    }
    for i in 1..n {
        let mut j = i;
        while j > 0 && set.obst_id[order[j - 1]] > set.obst_id[order[j]] {
            order.swap(j, j - 1);
            j -= 1;
        }
    }
    let mut buf = [0u8; 8 + CERT_SLOTS * 12];
    buf[..8].copy_from_slice(digest);
    let mut off = 8;
    for &o in order.iter().take(n) {
        buf[off..off + 4].copy_from_slice(&set.obst_id[o].to_le_bytes());
        off += 4;
        buf[off..off + 8].copy_from_slice(&set.obst_h[o]);
        off += 8;
    }
    let h = sha256(&buf[..off]);
    digest.copy_from_slice(&h[24..32]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_silent_members_changes_nothing() {
        let dev = Device::new();
        let mut g = std::boxed::Box::new(Grid::new());
        let mut set = ObstacleSet::new();
        let mut ids = [0u32; 4];
        assert_eq!(silent_obstacles(&dev, &mut g, &mut set, &[], 1_000_000_000, &mut ids), 0);
        assert!(g.stat.iter().all(|r| r.iter().all(|&c| c == 0)));
        let mut d = [1u8, 2, 3, 4, 5, 6, 7, 8];
        fold_obstacles_into_digest(&set, &mut d);
        assert_eq!(d, [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn a_silent_member_is_drawn_and_a_voted_one_is_not() {
        let mut dev = Device::new();
        let f = Frame { magic: crate::FRAME_MAGIC, protocol_ver: 5, seg_id: 7, ttl_ms: 300, len_dm: 45, wid_dm: 18, pseudo_id: 0xA100, s_cm: 0, d_cm: 100, ..Default::default() };
        dev.certs[3].in_use = 1;
        dev.certs[3].proven = 1;
        dev.certs[3].have_frame = 1;
        dev.certs[3].pseudo_id = 0xA100;
        dev.certs[3].last_frame = f;
        dev.certs[3].last_ok_us = 1_000_000;
        let mut g = std::boxed::Box::new(Grid::new());
        let mut set = ObstacleSet::new();
        let mut ids = [0u32; 4];
        let now = 1_000_000 + MEMBER_SILENT_MS * 1000;
        assert_eq!(silent_obstacles(&dev, &mut g, &mut set, &[], now, &mut ids), 1);
        assert_eq!(ids[0], 0xA100);
        assert!(g.stat.iter().any(|r| r.iter().any(|&c| c == 1)));
        // the car that voted is frozen, not drawn
        dev.certs[3].voted = 1;
        let mut g2 = std::boxed::Box::new(Grid::new());
        assert_eq!(silent_obstacles(&dev, &mut g2, &mut set, &[], now, &mut ids), 0);
        assert_eq!(set.frozen_voted_n, 1);
        assert_eq!(set.frozen_voted_id, 0xA100);
    }
}
