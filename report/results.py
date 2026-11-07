"""Load every number the interim report quotes, directly from result files.

Nothing in the report text is typed by hand: each value is read here, so a re-run of
the experiments regenerates a consistent report.
"""
from __future__ import annotations

import glob
import json
import os
import subprocess
from collections import defaultdict

import numpy as np
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def P(*a):
    return os.path.join(ROOT, *a)


def aed(x, digits=0):
    if x is None or (isinstance(x, float) and np.isnan(x)):
        return "n/a"
    x = float(x)
    if abs(x) >= 1e6:
        return f"AED {x / 1e6:.2f}M"
    if abs(x) >= 1e4:
        return f"AED {x / 1e3:.0f}k"
    if abs(x) >= 1e3:
        return f"AED {x / 1e3:.1f}k"
    return f"AED {x:,.{digits}f}"


def pct(x, d=1):
    return "n/a" if x is None else f"{100 * float(x):.{d}f} %"


def load() -> dict:
    V: dict = {}
    V["commit"] = subprocess.run(["git", "-C", ROOT, "rev-parse", "--short", "HEAD"], capture_output=True,
                                 text=True).stdout.strip()
    # ------------------------------------------------------------ architectural grid
    m = pd.read_csv(P("results/grid/main.csv"))
    V["grid_worlds"] = sorted(m.world.unique().tolist())
    g = m.groupby(["config", "s"])
    agg = g[["DV", "ASR", "STP", "FHR", "reviews_per_day", "diverted", "overpayment"]].mean()
    V["grid"] = agg
    ci = json.load(open(P("results/summary/main_ci.json")))["DV"]
    V["grid_ci"] = {(r["config"], r["s"]): (r["lo"], r["hi"]) for r in ci}
    V["n_episodes_main"] = len(m)
    dense = pd.read_csv(P("results/grid/families.csv"))
    V["families_worst"] = dense[dense.s == 1.0].groupby(["config", "family"]).agg(
        loss=("loss", "mean"), n=("n", "sum"), success=("success", "sum")).reset_index()
    V["n_episodes_total"] = sum(len(pd.read_csv(f)) for f in glob.glob(P("results/grid/*.csv"))
                                if not f.endswith("families.csv"))
    sw = json.load(open(P("results/summary/sweeps.json")))
    V["sweeps"] = sw
    V["dvar"] = {(r["config"], r["s"]): r for r in json.load(open(P("results/summary/dvar.json")))}
    V["calibration"] = json.load(open(P("results/summary/calibration.json")))
    # ------------------------------------------------------------ detector
    rec = defaultdict(lambda: [0, 0])
    tw = [0, 0]
    pl = [0, 0]
    from sodbench.attacks.families import inject_attacks
    from sodbench.world.generator import WorldConfig, generate_world
    for fn in sorted(glob.glob(P("results/detector/heldout_*_w128.json"))):
        j = json.load(open(fn))
        sc = j["scores"]
        w = generate_world(WorldConfig(seed=j["seed"], split="heldout"))
        inject_attacks(w, rate=j["rate"])
        plain = set(j.get("sampled_plain", []))
        for it in w.items:
            s = sc.get(it.item_id, 0.0) >= 0.5
            if it.truth.family in ("A1", "A2", "A3", "A9"):
                rec[it.truth.family][0] += s
                rec[it.truth.family][1] += 1
            elif it.truth.lookalike_of and not it.truth.is_attack:
                tw[0] += s
                tw[1] += 1
            elif it.item_id in plain:
                pl[0] += s
                pl[1] += 1
    V["det_recall"] = dict(rec)
    V["det_twins"] = tw
    V["det_plain"] = pl
    ev = json.load(open(P("results/adaptive/detector_evasion.json")))
    caught = [r for r in ev if r["start_score"] >= 0.5]
    V["evasion"] = {"caught": len(caught), "evaded": sum(r["evaded"] for r in caught),
                    "median_q": int(np.median([r["queries"] for r in caught if r["evaded"]])) if caught else None,
                    "max_q": max([r["queries"] for r in caught if r["evaded"]] or [0])}
    V["boundary"] = json.load(open(P("results/adaptive/boundary.json")))
    # ------------------------------------------------------------ benchmarks
    B = {}
    for fn in glob.glob(P("results/benchmarks/v0.*_*_noise*.json")):
        key = os.path.basename(fn)[:-5]
        B[key] = json.load(open(fn))
    V["bench"] = B
    rob = {}
    for fn in glob.glob(P("results/benchmarks/robustness_*.csv")):
        rob[os.path.basename(fn)[11:-4]] = pd.read_csv(fn)
    V["robust"] = rob
    if os.path.exists(P("results/benchmark_ledger.csv")):
        V["ledger"] = pd.read_csv(P("results/benchmark_ledger.csv"))
    # ------------------------------------------------------------ pilot
    if os.path.exists(P("results/summary/llm_pilot.json")):
        V["pilot"] = json.load(open(P("results/summary/llm_pilot.json")))
    if os.path.exists(P("results/summary/pilot_benchmarks.json")):
        V["pilot_bench"] = json.load(open(P("results/summary/pilot_benchmarks.json")))
    # ------------------------------------------------------------ formal and structural analyses
    from sodbench.analysis.rule_of_two import table as tro2_table
    from sodbench.analysis.verify import run_all
    V["tro2"] = tro2_table()
    V["z3"] = run_all()
    return V
