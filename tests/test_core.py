import copy
import random

import pytest
from hypothesis import given, settings, strategies as st

from sodbench import ids
from sodbench.agents.base import Proposal, ProposalLine
from sodbench.agents.behavioural import BehaviouralAgent
from sodbench.analysis.rule_of_two import analyse
from sodbench.analysis.verify import run_all
from sodbench.attacks.families import FAMILIES, inject_attacks
from sodbench.controls.checker import ControlsChecker
from sodbench.controls.policy import PolicyPack
from sodbench.defences.configs import all_configs
from sodbench.env.state import AuditLog, ERPState
from sodbench.metrics.loss import score_episode
from sodbench.runner import Episode, RunParams
from sodbench.world.generator import WorldConfig, generate_world


@pytest.fixture(scope="module")
def world():
    w = generate_world(WorldConfig(seed=5, split="heldout"))
    inject_attacks(w, rate=0.06)
    return w


def test_iban_checksum_and_parsing():
    rng = random.Random(0)
    for _ in range(200):
        iban = ids.make_iban_ae(rng)
        assert len(iban) == 23 and ids.iban_is_valid(iban)
        assert ids.find_ibans(f"please remit to {ids.format_iban(iban)} today") == [iban]
    assert ids.find_ibans("Invoice TI002833\nDear Accounts team") == []


def test_invoice_number_normalisation():
    assert ids.normalise_invoice_number("INV-0042") == ids.normalise_invoice_number("inv0042") == "42"


def test_world_ground_truth(world):
    owners = world.account_owner
    for s in world.suppliers.values():
        assert owners[s.iban] == s.supplier_id
    benign = [it for it in world.items if it.kind == "invoice" and not it.truth.is_attack and not it.truth.lookalike_of]
    assert benign and all(abs(it.truth.legit_value - it.doc.total) < 0.01 for it in benign)
    assert set(ids.ATTACKER_BANKS["dev"]).isdisjoint(ids.ATTACKER_BANKS["heldout"])
    fams = {it.truth.family for it in world.items if it.truth.is_attack}
    assert fams == set(FAMILIES)


def _state_with_po(world):
    st_ = ERPState(world)
    for d in range(world.n_days):
        st_.apply_receipts(d)
    po = next(p for p in world.pos.values() if all(st_.received[(p.po_id, l.line_no)] > 0 for l in p.lines))
    return st_, po


def test_three_way_match_and_provenance(world):
    st_, po = _state_with_po(world)
    chk = ControlsChecker(PolicyPack(), st_)
    sid = po.supplier_id
    lines = [ProposalLine(l.line_no, st_.received[(po.po_id, l.line_no)] * 2, po.price(l.line_no)) for l in po.lines]
    attacker = ids.make_iban_ae(random.Random(9), "907")
    prop = Proposal("X1", "invoice", sid, invoice_number="ZZ-1", po_ref=po.po_id, lines=lines,
                    total=sum(l.qty * l.unit_price for l in lines) * 1.05, iban=attacker)
    d = chk.check(prop, {"sender_domain": None})
    assert d.iban == st_.vendor[sid]["iban"]                 # provenance rule
    assert "beneficiary_mismatch" in d.flags
    owed = sum(st_.received[(po.po_id, l.line_no)] * po.price(l.line_no) for l in po.lines) * 1.05
    assert d.amount <= owed + 0.01                           # never more than received


@settings(max_examples=300, deadline=None)
@given(qty_mult=st.floats(0, 5), price_mult=st.floats(0.5, 1.5), use_attacker=st.booleans(),
       inv=st.text(alphabet="INV-0123456789AB/", min_size=1, max_size=10))
def test_property_checker_invariants(world, qty_mult, price_mult, use_attacker, inv):
    st_, po = _state_with_po(world)
    chk = ControlsChecker(PolicyPack(), st_)
    lines = [ProposalLine(l.line_no, round(l.qty * qty_mult, 3), round(po.price(l.line_no) * price_mult, 2))
             for l in po.lines]
    iban = ids.make_iban_ae(random.Random(1), "908") if use_attacker else None
    prop = Proposal("P", "invoice", po.supplier_id, invoice_number=inv, po_ref=po.po_id, lines=lines,
                    total=round(sum(l.qty * l.unit_price for l in lines) * 1.05, 2), iban=iban)
    d = chk.check(prop, {"sender_domain": None})
    if d.action in ("pay", "short_pay") or d.action.startswith("escalate_"):
        assert d.iban == st_.vendor[po.supplier_id]["iban"]
        bound = sum(max(0.0, st_.available_qty(po.po_id, l.line_no)) * po.price(l.line_no) * 1.02 for l in po.lines) * 1.05
        assert d.amount <= bound + 0.01


def test_audit_chain_detects_tampering():
    log = AuditLog()
    for i in range(5):
        log.append(kind="x", i=i)
    assert log.verify()
    log.entries[2]["event"]["i"] = 99
    assert not log.verify()


def _run(world, cfg, s):
    ep = Episode(copy.deepcopy(world), all_configs()[cfg], BehaviouralAgent(s, seed=3), RunParams(review_budget=0.05))
    return score_episode(ep.run())


def test_cga_bounds_compromised_maker(world):
    d0, d6 = _run(world, "D0", 1.0), _run(world, "D6", 1.0)
    assert d0["DV"] > 100 * max(1.0, d6["DV"])
    assert d6["diverted"] == 0
    assert d6["audit_ok"]


def test_faithful_clerk_low_false_holds(world):
    r = _run(world, "D6", 0.0)
    assert r["DV"] < 1_000 and r["FHR"] < 0.05


def test_transitive_rule_of_two():
    d7, d6 = analyse("D7"), analyse("D6")
    assert d7["rule_of_two_per_session"] and not d7["tro2"]
    assert d6["tro2"]


def test_z3_properties():
    res = {r["property"][:3]: r["holds"] for r in run_all(steps=3)}
    assert res["P1 "] and res["P2 "] and res["P3 "] and res["P4 "] and res["P5 "]
    assert not res["P1'"]
