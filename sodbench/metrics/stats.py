"""Statistics: bootstrap confidence intervals, exact McNemar test, Wilson intervals,
diverted-value-at-risk (DVaR) and conditional DVaR, expected calibration error."""
from __future__ import annotations

import math
import random
from typing import Callable, Sequence


def mean(xs: Sequence[float]) -> float:
    return sum(xs) / len(xs) if xs else float("nan")


def bootstrap_ci(xs: Sequence[float], stat: Callable = mean, B: int = 2000, alpha: float = 0.05,
                 seed: int = 0) -> tuple[float, float]:
    if not xs:
        return (float("nan"), float("nan"))
    rng = random.Random(seed)
    n = len(xs)
    vals = sorted(stat([xs[rng.randrange(n)] for _ in range(n)]) for _ in range(B))
    return vals[int(alpha / 2 * B)], vals[int((1 - alpha / 2) * B) - 1]


def paired_bootstrap_diff(a: Sequence[float], b: Sequence[float], B: int = 2000, seed: int = 0):
    """CI for mean(a - b) over paired episodes, and the share of resamples with a <= b."""
    d = [x - y for x, y in zip(a, b)]
    lo, hi = bootstrap_ci(d, B=B, seed=seed)
    return mean(d), lo, hi


def mcnemar_exact(b: int, c: int) -> float:
    """Two-sided exact McNemar p-value; b, c = discordant pair counts."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    p = sum(math.comb(n, i) for i in range(0, k + 1)) / 2 ** n
    return min(1.0, 2 * p)


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    den = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / den
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return max(0.0, centre - half), min(1.0, centre + half)


def dvar(losses: Sequence[float], level: float = 0.95) -> float:
    """Diverted-value-at-risk: the loss not exceeded in ``level`` of periods."""
    s = sorted(losses)
    if not s:
        return float("nan")
    idx = min(len(s) - 1, max(0, math.ceil(level * len(s)) - 1))
    return s[idx]


def cvar(losses: Sequence[float], level: float = 0.95) -> float:
    """Conditional DVaR (expected shortfall): mean loss in the worst (1 - level) tail."""
    v = dvar(losses, level)
    tail = [x for x in losses if x >= v]
    return mean(tail)


def ece(probs: Sequence[float], labels: Sequence[int], bins: int = 10) -> float:
    n = len(probs)
    if n == 0:
        return float("nan")
    total = 0.0
    for b in range(bins):
        lo, hi = b / bins, (b + 1) / bins
        idx = [i for i, p in enumerate(probs) if (lo <= p < hi) or (b == bins - 1 and p == 1.0)]
        if not idx:
            continue
        conf = mean([probs[i] for i in idx])
        acc = mean([labels[i] for i in idx])
        total += len(idx) / n * abs(conf - acc)
    return total
