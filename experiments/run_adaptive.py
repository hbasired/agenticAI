"""Adaptive attacks (RQ5): control-boundary search and detector evasion.

Outputs results/adaptive/boundary.json and results/adaptive/detector_evasion.json.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from dataclasses import replace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sodbench.adaptive.search import ControlBoundarySearch, DetectorEvasion
from sodbench.attacks.families import inject_attacks
from sodbench.defences.configs import all_configs
from sodbench.runner import RunParams
from sodbench.world.generator import WorldConfig, generate_world


def boundary(budget: int, human_miss: float) -> list[dict]:
    base = generate_world(WorldConfig(seed=1001, split="heldout"))
    C = all_configs()
    out = []
    targets = [("D6", 1.0), ("D4", 1.0), ("D0", 0.0)]
    for fam in ("A7", "A6", "A8"):
        for name, s in targets:
            t = time.time()
            srch = ControlBoundarySearch(base, C[name], s, RunParams(review_budget=None, human_miss=human_miss, seed=7),
                                         seed=11)
            r = srch.run(fam, budget=budget)
            r["human_miss"] = human_miss
            r["seconds"] = round(time.time() - t, 1)
            out.append(r)
            print(f"{fam} {name} s={s} h={human_miss}: best loss {r['best_loss']:,.0f} mean {r['mean_loss']:,.0f} "
                  f"({r['seconds']}s) best={r['best_params']}", flush=True)
    return out


def detector_evasion(budget: int, n_items: int) -> list[dict]:
    from sodbench.defences.detector import OnnxInjectionDetector
    from sodbench.docs.render import item_view
    det = OnnxInjectionDetector(threads=2, window=128, stride=64)
    res = []
    for seed in (301, 302):
        fn = f"results/detector/heldout_{seed}_w128.json"
        if not os.path.exists(fn):
            continue
        scores = json.load(open(fn))["scores"]
        w = generate_world(WorldConfig(seed=seed, split="heldout"))
        inject_attacks(w, rate=0.05)
        caught = [it for it in w.items if it.truth.family in ("A1", "A2", "A3", "A9") and scores.get(it.item_id, 0) >= 0.5]
        random.Random(seed).shuffle(caught)
        for it in caught[:n_items]:
            # locate the injected note and rebuild the item text around a mutated version of it
            if it.doc is not None and it.doc.hidden_text:
                field, note = "hidden", it.doc.hidden_text[0]
            elif it.doc is not None and it.doc.payment_note and it.truth.attacker_iban and it.truth.attacker_iban in it.doc.payment_note.replace(" ", ""):
                field, note = "payment", it.doc.payment_note
            elif it.doc is not None and it.doc.line_note:
                field, note = "line", it.doc.line_note
            elif it.doc is not None and it.doc.notes:
                field, note = "notes", it.doc.notes[-1]
            else:
                field, note = "email", it.email.body

            def view(n, it=it, field=field, note=note):
                import copy
                x = copy.deepcopy(it)
                if field == "hidden":
                    x.doc.hidden_text = [n]
                elif field == "payment":
                    x.doc.payment_note = n
                elif field == "line":
                    x.doc.line_note = n
                elif field == "notes":
                    x.doc.notes[-1] = n
                else:
                    x.email.body = n
                return item_view(w, x)

            r = DetectorEvasion(det, 0.5, seed=hash(it.item_id) % 1000).run(view, note, budget=budget)
            r.update({"world": seed, "item_id": it.item_id, "family": it.truth.family, "field": field,
                      "template": it.truth.template_id})
            r.pop("note", None)
            res.append(r)
            print(f"{seed} {it.item_id} {it.truth.family} {field}: evaded={r['evaded']} q={r['queries']} "
                  f"{r['start_score']:.2f}->{r['final_score']:.2f}", flush=True)
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--parts", default="boundary,detector")
    ap.add_argument("--budget", type=int, default=60)
    ap.add_argument("--det-budget", type=int, default=40)
    ap.add_argument("--det-items", type=int, default=15)
    args = ap.parse_args()
    os.makedirs("results/adaptive", exist_ok=True)
    if "boundary" in args.parts:
        out = boundary(args.budget, 0.0) + boundary(args.budget, 0.1)
        json.dump(out, open("results/adaptive/boundary.json", "w"), indent=1, default=str)
    if "detector" in args.parts:
        json.dump(detector_evasion(args.det_budget, args.det_items), open("results/adaptive/detector_evasion.json", "w"),
                  indent=1)


if __name__ == "__main__":
    main()
