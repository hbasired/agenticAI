"""Machine-checked properties of the controls-as-code checker (Z3 SMT solver).

The checker's payable path is encoded symbolically; each property is proved by
showing that its negation is unsatisfiable for *all* proposals a maker could emit,
including adversarial ones. Removing a control turns the relevant proof into a
satisfiable query, and Z3 returns a concrete counterexample. These proofs cover the
abstract model; ``tests/test_properties.py`` checks the same invariants on the Python
implementation with property-based testing.
"""
from __future__ import annotations

import z3

TOL, VAT = 0.02, 1.05


def _step(prop_iban, master, provenance, qty, price, po_price, avail):
    beneficiary = z3.If(provenance, master, prop_iban)
    price_ok = price <= po_price * (1 + TOL)
    pay_qty = z3.If(qty < avail, qty, avail)
    pay_qty = z3.If(pay_qty < 0, 0, pay_qty)
    amount = z3.If(price_ok, pay_qty * price * VAT, 0)
    return beneficiary, amount, pay_qty


def prove(claim, *assumptions) -> tuple[bool, str]:
    s = z3.Solver()
    s.add(*assumptions)
    s.add(z3.Not(claim))
    r = s.check()
    if r == z3.unsat:
        return True, "proved"
    return False, str(s.model()) if r == z3.sat else "unknown"


def run_all(steps: int = 4) -> list[dict]:
    out = []
    master, prop_iban = z3.Ints("master prop_iban")
    qty, price, po_price, avail = z3.Reals("qty price po_price avail")
    base = [po_price > 0, avail >= 0, qty >= 0, price >= 0]

    b, amt, _ = _step(prop_iban, master, z3.BoolVal(True), qty, price, po_price, avail)
    ok, info = prove(b == master, *base)
    out.append({"property": "P1 beneficiary integrity (provenance rule on): payee account = verified master data",
                "holds": ok, "detail": info})
    b2, _, _ = _step(prop_iban, master, z3.BoolVal(False), qty, price, po_price, avail)
    ok, info = prove(b2 == master, *base)
    out.append({"property": "P1' same claim with the provenance rule removed (D6a)", "holds": ok,
                "detail": "counterexample: " + info if not ok else info})
    ok, info = prove(amt <= avail * po_price * (1 + TOL) * VAT, *base)
    out.append({"property": "P2 per-invoice overpayment bound: amount <= received-not-yet-paid x PO price x (1+tol) x VAT",
                "holds": ok, "detail": info})
    ok, info = prove(z3.Implies(avail == 0, amt == 0), *base)
    out.append({"property": "P3 no payment without an unpaid goods receipt", "holds": ok, "detail": info})

    # P4: cumulative bound over a sequence of adversarial proposals on one PO line (bounded model checking)
    received = z3.Real("received")
    cons = [received >= 0, po_price > 0]
    approved = z3.RealVal(0)
    total = z3.RealVal(0)
    for k in range(steps):
        q, p = z3.Reals(f"q{k} p{k}")
        cons += [q >= 0, p >= 0]
        avail_k = received - approved
        _, a_k, pq_k = _step(prop_iban, master, z3.BoolVal(True), q, p, po_price, avail_k)
        total = total + a_k
        approved = approved + z3.If(p <= po_price * (1 + TOL), pq_k, 0)
    ok, info = prove(total <= received * po_price * (1 + TOL) * VAT, *cons)
    out.append({"property": f"P4 cumulative bound over {steps} adversarial invoices on one PO line "
                            "(duplicates, splitting, re-issues)", "holds": ok, "detail": info})
    # P5: the residual the bound leaves: overpayment inside tolerance is reachable
    s = z3.Solver()
    s.add(*base, avail > 0, qty == avail, price == po_price * (1 + TOL))
    s.add(amt > avail * po_price * VAT)
    out.append({"property": "P5 residual: overpayment within price tolerance is reachable (H4)",
                "holds": s.check() == z3.sat, "detail": "satisfiable: tolerance is the residual attack surface"})
    return out


if __name__ == "__main__":
    for r in run_all():
        print(("PROVED " if r["holds"] else "FAILS  ") + r["property"] + " | " + r["detail"][:160])
