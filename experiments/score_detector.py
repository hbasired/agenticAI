"""Score every inbox item of the evaluation worlds with the real injection classifier (D2).

Scores use the exact text an agent receives (PDF text layer, flattened UBL, e-mail),
scanned in 128-token windows. Output: results/detector/<split>_<seed>.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sodbench.attacks.families import inject_attacks
from sodbench.defences.detector import OnnxInjectionDetector
from sodbench.docs.render import item_view
from sodbench.world.generator import WorldConfig, generate_world


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--worlds", default="dev:300,heldout:301,heldout:302")
    ap.add_argument("--rate", type=float, default=0.05)
    ap.add_argument("--window", type=int, default=128)
    ap.add_argument("--threads", type=int, default=1)
    ap.add_argument("--benign-sample", type=int, default=300)
    args = ap.parse_args()
    det = OnnxInjectionDetector(threads=args.threads, window=args.window, stride=args.window // 2)
    os.makedirs("results/detector", exist_ok=True)
    for spec in args.worlds.split(","):
        split, seed = spec.split(":")
        out = f"results/detector/{split}_{seed}_w{args.window}.json"
        if os.path.exists(out):
            continue
        w = generate_world(WorldConfig(seed=int(seed), split=split))
        inject_attacks(w, rate=args.rate)
        t = time.time()
        import random
        rng = random.Random(int(seed))
        special = [it for it in w.items if it.truth.is_attack or it.truth.lookalike_of]
        plain = [it for it in w.items if not (it.truth.is_attack or it.truth.lookalike_of)]
        sample = rng.sample(plain, min(args.benign_sample, len(plain)))
        scores = {it.item_id: round(det.score(item_view(w, it)), 5) for it in special + sample}
        json.dump({"split": split, "seed": int(seed), "rate": args.rate, "window": args.window,
                   "detector": det.name, "scores": scores, "sampled_plain": [it.item_id for it in sample],
                   "note": "unsampled plain items are treated as score 0; plain-item FPR is estimated on the sample"},
                  open(out, "w"))
        print(f"{out}: {len(scores)} items in {time.time() - t:.0f}s", flush=True)


if __name__ == "__main__":
    main()
