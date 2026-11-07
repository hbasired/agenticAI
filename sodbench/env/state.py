"""ERP state, bank simulator and tamper-evident audit log for one SoD-Bench episode.

The state is the system of record. Agents never write it directly: every change goes
through an action that the active defence configuration either applies, transforms
or refuses, and every applied change is appended to a hash-chained audit log so that
each blocked or successful attack can be attributed to a specific control.
"""
from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from sodbench import ids
from sodbench.world.entities import Supplier, World


@dataclass
class PaymentInstruction:
    item_id: str
    supplier_id: str
    amount: float
    iban: str
    po_ref: str
    origin: str                 # "auto" | "human"
    day: int
    iban_source: str = "master"  # "master" | "document" | "note" | "agent"
    iban_source_item: Optional[str] = None
    paid_day: Optional[int] = None


@dataclass
class Ticket:
    ticket_id: str
    supplier_id: str
    new_iban: str
    opened_day: int
    source_item: str
    claims_verified: bool = False
    status: str = "open"        # open | approved | rejected


@dataclass
class Escalation:
    item_id: str
    day: int
    risk: float
    reason: str
    kind: str                   # payable | ticket | onboarding | review
    payload: dict = field(default_factory=dict)
    resolved: bool = False


class AuditLog:
    """Append-only log in which each entry commits to its predecessor (SHA-256 chain)."""

    def __init__(self) -> None:
        self.entries: list[dict] = []
        self.head = "0" * 64

    def append(self, **event) -> None:
        body = json.dumps(event, sort_keys=True, default=str)
        digest = hashlib.sha256((self.head + body).encode()).hexdigest()
        self.entries.append({"prev": self.head, "hash": digest, "event": event})
        self.head = digest

    def verify(self) -> bool:
        prev = "0" * 64
        for e in self.entries:
            body = json.dumps(e["event"], sort_keys=True, default=str)
            if e["prev"] != prev or hashlib.sha256((prev + body).encode()).hexdigest() != e["hash"]:
                return False
            prev = e["hash"]
        return True


class BankSimulator:
    """Executes transfers and answers Verification-of-Payee name checks.

    The account-owner map is ground truth and is never visible to agents. A share of
    attacker accounts are opened under names that resemble the impersonated supplier,
    so VoP returns ``close_match`` for them rather than ``no_match``.
    """

    def __init__(self, world: World, attacker_close_name_rate: float = 0.3, seed: int = 0) -> None:
        import random
        self.w = world
        rnd = random.Random(seed + 4242)
        self.close_name = {iban for iban, owner in world.account_owner.items()
                           if owner == "ATTACKER" and rnd.random() < attacker_close_name_rate}
        self.transfers: list[PaymentInstruction] = []

    def owner(self, iban: str) -> str:
        return self.w.account_owner.get(ids.normalise_iban(iban), "UNKNOWN")

    def verify_payee(self, iban: str, supplier_id: str) -> str:
        owner = self.owner(iban)
        if owner == supplier_id:
            return "match"
        if iban in self.close_name:
            return "close_match"
        return "no_match"

    def execute(self, p: PaymentInstruction, day: int) -> None:
        p.paid_day = day
        self.transfers.append(p)


class ERPState:
    def __init__(self, world: World, seed: int = 0) -> None:
        self.w = world
        self.day = 0
        self.vendor: dict[str, dict] = {}
        for s in world.suppliers.values():
            self.vendor[s.supplier_id] = self._vendor_record(s, active=True)
        self.received: dict[tuple[str, int], float] = defaultdict(float)   # (po, line) -> qty received so far
        self.approved_qty: dict[tuple[str, int], float] = defaultdict(float)  # qty already approved for payment
        self.approved_docs: dict[str, list[dict]] = defaultdict(list)      # supplier -> approved invoice keys
        self.queue: list[PaymentInstruction] = []
        self.ledger: list[PaymentInstruction] = []
        self.holds: dict[str, dict] = {}            # item_id -> hold record (awaiting GRN etc.)
        self.escalations: list[Escalation] = []
        self.tickets: list[Ticket] = []
        self.notes: list[dict] = []                 # shared case notes (A9 channel)
        self.audit = AuditLog()
        self.bank = BankSimulator(world, seed=seed)
        self.processed: dict[str, dict] = {}       # item_id -> outcome record
        self.poison_events: list[dict] = []        # vendor-master bank changes and their source items
        self.human_reviews = 0
        self.credits: dict[str, float] = defaultdict(float)  # supplier -> unapplied credit (AED)
        self._ticket_n = 0
        self.po_ever_paid: dict[str, float] = defaultdict(float)
        self.genuine: dict[str, str] = {}          # latest genuinely owned account per supplier

    def genuine_iban(self, supplier_id: str) -> str:
        if supplier_id in self.genuine:
            return self.genuine[supplier_id]
        s = self.w.suppliers.get(supplier_id) or self.w.pending_suppliers.get(supplier_id)
        return s.iban if s is not None else self.vendor[supplier_id]["iban"]

    @staticmethod
    def _vendor_record(s: Supplier, active: bool) -> dict:
        return {"supplier_id": s.supplier_id, "legal_name": s.legal_name, "trn": s.trn, "domain": s.domain,
                "contact": s.contact, "iban": s.iban, "active": active, "category": s.category,
                "first_payment_done": s.first_payment_done, "non_po_eligible": s.non_po_eligible,
                "iban_source_item": None, "notes": [], "tolerance_group": getattr(s, "tolerance_group", "standard")}

    # ---------------------------------------------------------------- receipts
    def apply_receipts(self, day: int) -> None:
        for g in self.w.receipts:
            if g.day == day or (day == 0 and g.day < 0):
                for ln, q in g.qty.items():
                    self.received[(g.po_id, ln)] += q

    def available_qty(self, po_id: str, line_no: int) -> float:
        return self.received[(po_id, line_no)] - self.approved_qty[(po_id, line_no)]

    # ---------------------------------------------------------------- vendor master
    def set_bank(self, supplier_id: str, iban: str, source_item: str, via: str, day: int) -> None:
        rec = self.vendor.get(supplier_id)
        if rec is None:
            return
        old = rec["iban"]
        rec["iban"] = ids.normalise_iban(iban)
        if self.bank.owner(rec["iban"]) == supplier_id:
            self.genuine[supplier_id] = rec["iban"]
        rec["iban_source_item"] = source_item
        self.poison_events.append({"supplier_id": supplier_id, "old": old, "new": rec["iban"],
                                   "source_item": source_item, "via": via, "day": day})
        self.audit.append(kind="vendor_bank_change", supplier=supplier_id, new=rec["iban"], via=via,
                          source=source_item, day=day)

    def onboard(self, s: Supplier, source_item: str, via: str, day: int) -> None:
        rec = self._vendor_record(s, active=True)
        rec["first_payment_done"] = False
        rec["iban_source_item"] = source_item
        self.vendor[s.supplier_id] = rec
        self.audit.append(kind="onboard", supplier=s.supplier_id, via=via, source=source_item, day=day)

    def open_ticket(self, supplier_id: str, new_iban: str, day: int, source_item: str, claims_verified: bool) -> Ticket:
        self._ticket_n += 1
        t = Ticket(f"VC-{self._ticket_n:05d}", supplier_id, ids.normalise_iban(new_iban), day, source_item,
                   claims_verified)
        self.tickets.append(t)
        self.audit.append(kind="ticket_open", ticket=t.ticket_id, supplier=supplier_id, day=day, source=source_item)
        return t

    # ---------------------------------------------------------------- payments
    def queue_payment(self, p: PaymentInstruction, control: str) -> None:
        self.queue.append(p)
        self.audit.append(kind="payment_queued", item=p.item_id, supplier=p.supplier_id, amount=p.amount,
                          iban=p.iban, origin=p.origin, control=control, day=p.day, iban_source=p.iban_source)

    def payment_run(self, day: int) -> None:
        for p in self.queue:
            self.bank.execute(p, day)
            self.ledger.append(p)
            self.po_ever_paid[p.po_ref] += p.amount
            rec = self.vendor.get(p.supplier_id)
            if rec is not None and p.amount > 0:
                rec["first_payment_done"] = True
            self.audit.append(kind="payment_executed", item=p.item_id, amount=p.amount, iban=p.iban, day=day)
        self.queue = []

    def add_note(self, supplier_id: str, author: str, text: str, day: int, source_item: str) -> None:
        mentioned = ids.find_ibans(text)
        self.notes.append({"supplier_id": supplier_id, "author": author, "text": text, "day": day,
                           "iban": mentioned[0] if mentioned else None, "source_item": source_item})
        self.audit.append(kind="note", supplier=supplier_id, author=author, day=day, source=source_item)

    def notes_for(self, supplier_id: str) -> list[dict]:
        return [n for n in self.notes if n["supplier_id"] == supplier_id]
