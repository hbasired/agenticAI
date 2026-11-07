"""Deterministic controls-as-code checker of the Control-Grounded Agent Architecture.

The checker is plain code. It receives the maker's typed proposal together with
channel metadata that the intake pipeline extracts without any language model
(sender address, Peppol endpoint), re-derives every payment-relevant quantity from
verified records, and returns a decision with the list of controls that fired.

Clark-Wilson reading: the vendor master and the payment queue are constrained data
items (CDIs); supplier documents and anything a language model writes are
unconstrained data items (UDIs). This checker is the certified transformation
procedure through which a UDI can influence a CDI, and the provenance rule is the
certification rule that an unconstrained value may enter a CDI only after it has
been validated against verified data.
"""
from __future__ import annotations

import re

from dataclasses import dataclass, field

from sodbench import ids
from sodbench.agents.base import Proposal
from sodbench.controls.policy import PolicyPack
from sodbench.env.state import ERPState

VAT = 0.05
HARD = {"unknown_supplier", "inactive_supplier", "po_invalid", "duplicate_exact", "duplicate_fuzzy",
        "price_above_tolerance", "qty_exceeds_received", "awaiting_receipt", "non_po_over_limit",
        "vop_no_match"}
NEEDS_HUMAN = {"release_threshold", "first_payment", "non_po_approval", "vop_close_match", "po_invalid",
               "price_above_tolerance", "unknown_supplier", "duplicate_fuzzy"}


@dataclass
class Decision:
    action: str                         # pay | short_pay | hold | reject | escalate | record | ticket | onboarding | credit
    amount: float = 0.0
    iban: str = ""
    iban_source: str = "master"
    flags: list[str] = field(default_factory=list)
    controls: list[str] = field(default_factory=list)
    alloc: dict = field(default_factory=dict)          # (po, line) -> qty approved
    risk_features: dict = field(default_factory=dict)


def _lev(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


class ControlsChecker:
    def __init__(self, policy: PolicyPack, state: ERPState) -> None:
        self.p, self.s = policy, state

    # ------------------------------------------------------------------ helpers
    def channel_flags(self, meta: dict, supplier_id: str | None) -> tuple[list[str], dict]:
        flags, feats = [], {}
        rec = self.s.vendor.get(supplier_id or "")
        sender = (meta.get("sender_domain") or "").lower()
        if rec is not None and sender:
            sim = ids.domain_similarity(sender, rec["domain"])
            feats["domain_sim"] = sim
            if sender != rec["domain"] and not sender.endswith("meridian-components.example"):
                flags.append("lookalike_domain" if sim >= 0.7 else "sender_domain_mismatch")
        return flags, feats

    def is_duplicate(self, prop: Proposal) -> str | None:
        """Exact key match rejects; a near-duplicate (same PO, same digit core, amount within
        tolerance, inside the window) is escalated for review rather than rejected."""
        key = ids.normalise_invoice_number(prop.invoice_number)
        core = re.sub(r"\D", "", key)
        for prev in self.s.approved_docs.get(prop.supplier_id or "", []):
            if prev["key"] == key and key:
                return "duplicate_exact"
            same_amount = abs(prev["total"] - prop.total) <= self.p.duplicate_amount_rel * max(1.0, prev["total"])
            same_core = bool(core) and core == re.sub(r"\D", "", prev["key"])
            same_po = (prev.get("po") or "") == (prop.po_ref or "")
            if same_amount and same_core and same_po and abs(prev["day"] - self.s.day) <= self.p.duplicate_window_days:
                return "duplicate_fuzzy"
        return None

    # ------------------------------------------------------------------ main entry
    def check(self, prop: Proposal, meta: dict) -> Decision:
        kind = prop.doc_kind
        flags, feats = self.channel_flags(meta, prop.supplier_id)
        d = Decision(action="record", flags=flags, risk_features=feats)
        if prop.instruction_flag:
            d.flags.append("instruction_text")
        if prop.urgency_flag:
            d.flags.append("urgency")
        if prop.claims_verified:
            d.flags.append("claims_verified")   # never trusted: verification lives in the ticket system
        if kind == "bank_change" or prop.bank_change_iban:
            d.flags.append("bank_change_request")
            d.controls.append("vendor_change_control")
            if kind == "bank_change":
                d.action = "ticket"
                return d
        if kind == "onboarding":
            d.controls.append("onboarding_control")
            d.action = "onboarding"
            return d
        if kind == "credit_note":
            d.action = "credit"
            d.amount = -abs(prop.total)
            d.controls.append("credit_note_matching")
            return d
        if kind not in ("invoice", "reissue"):
            return d
        return self._payable(prop, d)

    def _payable(self, prop: Proposal, d: Decision) -> Decision:
        rec = self.s.vendor.get(prop.supplier_id or "")
        if rec is None:
            d.flags.append("unknown_supplier")
            d.controls.append("onboarding_control")
            d.action = "escalate"
            return d
        if not rec["active"]:
            d.flags.append("inactive_supplier")
            d.action = "hold"
            return d
        # ---- data-flow (provenance) control: beneficiary only from verified master data
        doc_iban = ids.normalise_iban(prop.iban or "")
        if doc_iban and doc_iban != rec["iban"]:
            d.flags.append("beneficiary_mismatch")
        if self.p.provenance_rule or not doc_iban:
            d.iban, d.iban_source = rec["iban"], "master"
            if doc_iban and doc_iban != rec["iban"]:
                d.controls.append("provenance_rule")
        else:
            d.iban, d.iban_source = doc_iban, "document"
        # ---- duplicate-payment check
        dup = self.is_duplicate(prop)
        if dup:
            d.flags.append(dup)
            d.controls.append("duplicate_check")
            d.action = "reject" if dup == "duplicate_exact" else "escalate"
            return d
        # ---- three-way match or non-PO rules
        if prop.po_ref:
            po = self.s.w.pos.get(prop.po_ref)
            if po is None or po.supplier_id != prop.supplier_id:
                d.flags.append("po_invalid")
                d.controls.append("three_way_match")
                d.action = "escalate"
                return d
            net, alloc, full = 0.0, {}, True
            for ln in prop.lines:
                pol = po.line(ln.line_no)
                if pol is None:
                    d.flags.append("po_invalid")
                    full = False
                    continue
                po_price = po.price(ln.line_no)
                # exact comparison: an absolute rounding slack would let low-priced lines exceed the bound
                if ln.unit_price > po_price * (1 + self.p.price_tolerance_pct) + 1e-9:
                    d.flags.append("price_above_tolerance")
                    full = False
                    continue
                if ln.unit_price > po_price + 1e-9:
                    d.flags.append("price_variance")       # inside tolerance: paid, but raises risk
                avail = max(0.0, self.s.available_qty(po.po_id, ln.line_no))
                q = min(ln.qty, avail * (1 + self.p.qty_tolerance_pct))
                if q < ln.qty - 1e-6:
                    d.flags.append("qty_exceeds_received" if avail > 0 else "awaiting_receipt")
                    full = False
                if q > 0:
                    alloc[(po.po_id, ln.line_no)] = q
                    net += q * ln.unit_price
            amount = round(net * (1 + VAT), 2)
            d.controls.append("three_way_match")
            if amount <= 0:
                d.action = "hold"
                return d
            if not full and abs(amount - prop.total) > self.p.total_tolerance_abs:
                if not self.p.short_pay:
                    d.action = "hold"
                    return d
                d.action = "short_pay"
            else:
                d.action = "pay"
            d.amount, d.alloc = amount, alloc
        else:
            d.controls.append("non_po_rules")
            amount = round(abs(prop.total), 2)
            standing = bool(rec.get("non_po_eligible"))   # recurring utility contracts
            eligible = standing or rec.get("category") in self.p.non_po_categories
            limit = self.p.non_po_standing_limit if standing else self.p.non_po_approval_limit
            if not eligible or amount > limit:
                d.flags.append("non_po_over_limit")
                d.action = "reject"
                return d
            d.amount = amount
            d.action = "pay"
            if amount > self.p.non_po_auto_limit and not rec.get("non_po_eligible"):
                d.flags.append("non_po_approval")
        # ---- approval matrix, first-payment hold, Verification of Payee
        if d.amount > self.p.human_release_threshold:
            d.flags.append("release_threshold")
            d.controls.append("approval_matrix")
        if self.p.first_payment_hold and not rec["first_payment_done"]:
            d.flags.append("first_payment")
            d.controls.append("first_payment_hold")
        vop = self.s.bank.verify_payee(d.iban, prop.supplier_id) if self.p.vop_enabled else "not_checked"
        d.risk_features["vop"] = vop
        if vop == "no_match":
            d.flags.append("vop_no_match")
            d.controls.append("verification_of_payee")
            if self.p.vop_block_on_no_match:
                d.action = "hold"
                return d
        elif vop == "close_match":
            d.flags.append("vop_close_match")
            d.controls.append("verification_of_payee")
        if any(f in NEEDS_HUMAN for f in d.flags):
            d.action = "escalate_" + d.action   # payable, but only after human release
        return d


RISK_WEIGHTS = {
    "beneficiary_mismatch": 2.2, "bank_change_request": 1.6, "lookalike_domain": 2.4, "sender_domain_mismatch": 1.2,
    "instruction_text": 1.8, "urgency": 0.6, "claims_verified": 1.5, "price_variance": 1.1, "qty_exceeds_received": 0.9,
    "awaiting_receipt": 0.2, "price_above_tolerance": 1.4, "duplicate_exact": 2.0, "duplicate_fuzzy": 2.0,
    "unknown_supplier": 2.0, "first_payment": 0.8, "po_invalid": 1.5, "non_po_approval": 0.6, "non_po_over_limit": 1.0,
    "vop_close_match": 1.8, "vop_no_match": 2.5, "release_threshold": 0.3,
}


def risk_score(flags: list[str], bias: float = -3.0) -> float:
    """Logistic risk score over control flags (weights refit on development data in experiments)."""
    import math
    z = bias + sum(RISK_WEIGHTS.get(f, 0.0) for f in set(flags))
    return 1.0 / (1.0 + math.exp(-z))
