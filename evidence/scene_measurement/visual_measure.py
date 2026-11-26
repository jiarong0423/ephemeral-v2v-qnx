#!/usr/bin/env python3
"""visual_measure.py - the visual judgement behind the scene table SIM[], written down as a tool.

Measurements on one clip frame, from hand-picked points stored in a JSON file (each section is optional):
  1. Gutter grid: the gutter next to the kerb is a standard 18 in (45.72 cm) wide strip. At the image row of a
     wheel's ground contact, the kerb face and the gutter seam give one cell; the wheel's distance from the kerb face
     is counted in cells. This gives car A's gap to the kerb at each of its kerb-side wheels.
  2. Ground-plane depth: on a flat road, distance along the camera axis is proportional to 1 / (y - horizon_y).
     Car B's two wheels (wheelbase known) fix the scale. This places the parked white SUV's rear, car C's front
     wheel and the person along the street. The horizon is not visible in the frame, so it is swept over several
     candidates and every result is reported as a range.
  3. Own-width scale: at the image row of a car's front axle, the two outer wheel edges span the car's known width;
     that scale converts the kerb-to-wheel distance on the same row. Used on the 6 s frame, filmed from ahead of car A.
The results are compared with SIM[] in qnx_target/src/v2v_ttl_resmgr.c (--check); an overlay image shows every point.

usage: python3 -I evidence/scene_measurement/visual_measure.py <points.json> [--check] [--overlay <out.png>]
exit codes: 0 ok, 1 a check is outside its tolerance, 2 bad input (missing file, sha256 mismatch, bad JSON, SIM not found)
log: evidence/scene_measurement/visual_measure.log (appended)
"""
import argparse
import hashlib
import json
import logging
import math
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
SIM_SRC = REPO / "qnx_target" / "src" / "v2v_ttl_resmgr.c"
LOG = HERE / "visual_measure.log"

log = logging.getLogger("visual_measure")


def setup_logging():
    log.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    fh = logging.FileHandler(LOG, encoding="utf-8")
    fh.setFormatter(fmt)
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    log.addHandler(fh)
    log.addHandler(sh)


class InputError(Exception):
    pass


def x_on_line(line, y):
    """x of the image line through two points at image row y."""
    (x0, y0), (x1, y1) = line
    if y1 == y0:
        raise InputError(f"horizontal line {line} cannot be sampled by row")
    return x0 + (y - y0) * (x1 - x0) / (y1 - y0)


def gutter_grid(cfg):
    g = cfg["gutter_grid"]
    cell = float(g["cell_cm"])
    out = {}
    for name, (wx, wy) in g["wheels"].items():
        kx = x_on_line(g["kerb_face"], wy)
        sx = x_on_line(g["gutter_seam"], wy)
        cell_px = sx - kx
        if cell_px <= 0:
            raise InputError(f"{name}: gutter seam is not outside the kerb face at y={wy}")
        cells = (wx - kx) / cell_px
        out[name] = {"row_y": wy, "kerb_x": round(kx, 1), "seam_x": round(sx, 1), "cell_px": round(cell_px, 1),
                     "cells": round(cells, 2), "cm": round(cells * cell, 1)}
        log.info("grid %s: kerb x %.1f, seam x %.1f, one cell %.1f px, wheel x %.1f -> %.2f cells = %.0f cm",
                 name, kx, sx, cell_px, wx, cells, cells * cell)
    return out


def ground_depth(cfg):
    gd = cfg["ground_depth"]
    ref = gd["reference"]
    yr, yf = float(ref["rear_wheel_y"]), float(ref["front_wheel_y"])
    along = float(ref["wheelbase_cm"]) * abs(math.cos(math.radians(float(ref["heading_deg"]))))
    out = {name: [] for name in gd["points"]}
    for h in gd["horizon_y_candidates"]:
        h = float(h)
        if not (yr > h and yf > h):
            raise InputError(f"horizon {h} is not above both reference wheels")
        ratio = (yr - h) / (yf - h)
        if ratio <= 1.0:
            raise InputError("the front wheel must be higher in the frame (further) than the rear wheel")
        d_rear = along / (ratio - 1.0)
        for name, y in gd["points"].items():
            y = float(y)
            if y <= h:
                raise InputError(f"{name} at y={y} is above the horizon candidate {h}")
            depth = d_rear * (yr - h) / (y - h)
            s = float(ref["rear_wheel_s_cm"]) - (depth - d_rear)   # camera at +s looking toward -s
            out[name].append({"horizon_y": h, "depth_cm": round(depth, 1), "s_cm": round(s, 1)})
        log.info("depth horizon y=%.0f: B rear wheel %.0f cm from the camera", h, d_rear)
    for name, rows in out.items():
        ss = [r["s_cm"] for r in rows]
        log.info("depth %s: s from %.0f to %.0f cm", name, min(ss), max(ss))
    return out


def width_scale(cfg):
    ws = cfg["width_scale"]
    out = {}
    for name, m in ws["cars"].items():
        (lx, ly), (rx, ry) = m["left_wheel_outer"], m["right_wheel_outer"]
        row = (ly + ry) / 2.0
        px_per_cm = (rx - lx) / float(m["width_cm"])
        if px_per_cm <= 0:
            raise InputError(f"{name}: right wheel must be right of the left wheel")
        kx = x_on_line(ws["kerb_face"], row)
        cm = (lx - kx) / px_per_cm
        out[name] = {"row_y": round(row, 1), "kerb_x": round(kx, 1), "px_per_cm": round(px_per_cm, 3), "cm": round(cm, 1)}
        log.info("width scale %s: %.3f px/cm from its %.0f cm width, kerb x %.1f, wheel x %.1f -> %.0f cm from the kerb",
                 name, px_per_cm, float(m["width_cm"]), kx, lx, cm)
    return out


def read_sim():
    if not SIM_SRC.is_file():
        raise InputError(f"SIM source not found: {SIM_SRC}")
    text = SIM_SRC.read_text(encoding="utf-8")
    m = re.search(r"static const sim_obs_t SIM\[SIM_N_OBS\] = \{(.*?)\n\};", text, re.S)
    if not m:
        raise InputError("SIM[] table not found in the source")
    rows = {}
    for r in re.finditer(r'\{"([^"]+)",\s*[^,]+,\s*[^,]+,\s*([-\d.]+),\s*([-\d.]+),\s*([-\d.]+),\s*([-\d.]+),\s*([-\d.]+)\}',
                         m.group(1)):
        rows[r.group(1)] = {"s": float(r.group(2)), "d": float(r.group(3)), "h": float(r.group(4)),
                            "len": float(r.group(5)), "wid": float(r.group(6))}
    if not rows:
        raise InputError("SIM[] table has no rows")
    return rows


def sim_point(row, spec):
    c = math.cos(math.radians(row["h"]))
    if spec["end"] == "rear":
        return row["s"] - row["len"] / 2 * c
    if spec["end"] == "front_wheel":
        return row["s"] + float(spec["wheelbase_cm"]) / 2 * c
    if spec["end"] == "centre":
        return row["s"]
    raise InputError(f"unknown end {spec['end']}")


def sim_kerb_gaps(rows, kerb_d):
    """kerb-side corners of car A: distance from the near kerb at its two ends (end toward -s first)."""
    a = rows["Car A"]
    h = math.radians(a["h"])
    c, n = math.cos(h), math.sin(h)
    corners = []
    for x in (-a["len"] / 2, a["len"] / 2):
        y = -a["wid"] / 2
        corners.append(a["d"] + x * n + y * c - kerb_d)
    return corners


def check(cfg, grid, depth, widths):
    sc = cfg["sim_check"]
    rows = read_sim()
    bad = 0
    tol = float(sc.get("tolerance_cm", 0))
    for name, spec in sc.get("expect", {}).items():
        if spec["sim_name"] not in rows:
            raise InputError(f"SIM row {spec['sim_name']} not found")
        sim_s = sim_point(rows[spec["sim_name"]], spec)
        ss = [r["s_cm"] for r in depth[name]]
        lo, hi = min(ss) - tol, max(ss) + tol
        ok = lo <= sim_s <= hi
        bad += not ok
        log.log(logging.INFO if ok else logging.ERROR, "check %s: SIM s %.0f cm, frame %.0f..%.0f cm (+/- %.0f) -> %s",
                name, sim_s, min(ss), max(ss), tol, "PASS" if ok else "FAIL")
    ke = sc.get("kerb_expect")
    if not ke:
        return bad
    kt = float(ke["tolerance_cm"])
    far, near = sim_kerb_gaps(rows, kerb_d=-230.0)
    meas_all = {**grid, **widths}
    for name, sim_cm in (("A_far_left_wheel", far), ("A_near_left_wheel", near), ("Car A", (far + near) / 2)):
        if name not in ke or name not in meas_all:
            continue
        meas = meas_all[name]["cm"]
        ok = abs(meas - float(ke[name])) <= kt and abs(sim_cm - float(ke[name])) <= kt
        bad += not ok
        log.log(logging.INFO if ok else logging.ERROR, "check %s: frame %.0f cm, SIM corner %.0f cm, expected %.0f +/- %.0f -> %s",
                name, meas, sim_cm, float(ke[name]), kt, "PASS" if ok else "FAIL")
    return bad


def overlay(cfg, frame_path, out_png):
    from PIL import Image, ImageDraw
    im = Image.open(frame_path).convert("RGB")
    d = ImageDraw.Draw(im)
    g = cfg["gutter_grid"]
    for line, col in ((g["kerb_face"], (255, 0, 0)), (g["gutter_seam"], (0, 220, 0))):
        d.line([tuple(line[0]), tuple(line[1])], fill=col, width=2)
    for name, (wx, wy) in g["wheels"].items():
        kx, sx = x_on_line(g["kerb_face"], wy), x_on_line(g["gutter_seam"], wy)
        for i in range(4):
            x = kx + i * (sx - kx)
            d.line([(x, wy - 6), (x, wy + 6)], fill=(255, 230, 0), width=2)
        d.line([(kx, wy), (kx + 3 * (sx - kx), wy)], fill=(255, 230, 0), width=1)
        d.ellipse([wx - 4, wy - 4, wx + 4, wy + 4], outline=(0, 160, 255), width=2)
    gd = cfg["ground_depth"]
    for y in (gd["reference"]["rear_wheel_y"], gd["reference"]["front_wheel_y"], *gd["points"].values()):
        d.line([(0, y), (im.width, y)], fill=(0, 160, 255), width=1)
    for h in gd["horizon_y_candidates"]:
        d.line([(0, h), (im.width, h)], fill=(200, 0, 200), width=1)
    im.save(out_png)
    log.info("overlay written: %s", out_png)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("points")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--overlay")
    a = ap.parse_args()
    setup_logging()
    try:
        cfg_path = Path(a.points)
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        frame = (cfg_path.parent / cfg["frame"]).resolve()
        if not frame.is_file():
            raise InputError(f"frame not found: {frame}")
        sha = hashlib.sha256(frame.read_bytes()).hexdigest()
        if sha != cfg["frame_sha256"]:
            raise InputError(f"frame sha256 {sha} does not match {cfg['frame_sha256']}")
        log.info("frame %s sha256 %s", frame.name, sha)
        grid = gutter_grid(cfg) if "gutter_grid" in cfg else {}
        depth = ground_depth(cfg) if "ground_depth" in cfg else {}
        widths = width_scale(cfg) if "width_scale" in cfg else {}
        if a.overlay and "gutter_grid" in cfg and "ground_depth" in cfg:
            overlay(cfg, frame, a.overlay)
        bad = check(cfg, grid, depth, widths) if a.check else 0
    except (InputError, KeyError, ValueError, OSError, json.JSONDecodeError) as e:
        log.error("ERROR: %s", e)
        return 2
    if bad:
        log.error("ERROR: %d check(s) outside tolerance", bad)
        return 1
    log.info("RESULT: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
