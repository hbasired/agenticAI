"""Core data model of the SoD-Bench procure-to-pay world.

Everything an agent can see (documents, e-mails) is kept separate from the ground
truth that scoring uses (``GroundTruth``), so that utility and loss are computed
from environment state and never depend on a judge model.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import date
from typing import Optional


@dataclass
class Contact:
    name: str
    email: str
    phone: str


@dataclass
class Supplier:
    supplier_id: str
    legal_name: str
    trn: str
    address: str
    emirate: str
    category: str
    domain: str
    contact: Contact            # contact on file, used for call-back verification
    iban: str                   # verified beneficiary account in master data
    payment_terms_days: int
    non_po_eligible: bool       # utilities and similar may invoice without a PO
    onboarded_day: int          # negative = before the simulated period
    pool: str                   # "dev" or "heldout": which attack split may target it
    first_payment_done: bool = True
    surcharge: float = 0.0              # habitual, agreed surcharge on every invoice (owed; realism condition)
    tolerance_group: str = "standard"   # vendor tolerance group in master data ("standard" | "surcharge")
    invoice_style: str = "INV-{n:04d}"
    invoice_prefix: str = "AB"
    next_invoice_no: int = 1000


@dataclass
class Employee:
    emp_id: str
    name: str
    role: str
    approval_limit: float


@dataclass
class POLine:
    line_no: int
    item_code: str
    description: str
    uom: str
    qty: float
    unit_price: float


@dataclass
class PurchaseOrder:
    po_id: str
    supplier_id: str
    buyer_id: str
    created_day: int
    lines: list[POLine]
    amended_prices: dict[int, float] = field(default_factory=dict)  # contract-backed amendments

    def price(self, line_no: int) -> float:
        if line_no in self.amended_prices:
            return self.amended_prices[line_no]
        return next(l.unit_price for l in self.lines if l.line_no == line_no)

    def line(self, line_no: int) -> Optional[POLine]:
        return next((l for l in self.lines if l.line_no == line_no), None)


@dataclass
class GoodsReceipt:
    grn_id: str
    po_id: str
    day: int
    qty: dict[int, float]       # line_no -> quantity received (negative = return)


@dataclass
class DocLine:
    line_no: int                # PO line referenced (0 for non-PO)
    description: str
    qty: float
    unit_price: float
    uom: str = "pcs"

    @property
    def net(self) -> float:
        return round(self.qty * self.unit_price, 2)


@dataclass
class Document:
    """An invoice or credit note as issued by (or claimed to be from) a supplier."""
    doc_id: str
    kind: str                   # "invoice" | "credit_note"
    channel: str                # "pdf" | "ubl"
    supplier_name: str          # as printed on the document
    supplier_trn: str
    supplier_id_claimed: str    # what a correct extractor would resolve (may be fake)
    invoice_number: str
    issue_day: int
    po_ref: str                 # "" for non-PO invoices
    lines: list[DocLine]
    vat_rate: float
    iban: str                   # payee account printed on the document
    notes: list[str] = field(default_factory=list)          # visible free text
    hidden_text: list[str] = field(default_factory=list)    # PDF text layer only (white/tiny)
    line_note: str = ""         # free text inside an item description (UBL channel)
    payment_note: str = ""      # PaymentMeans instruction note (UBL channel)
    billing_reference: str = "" # referenced invoice (credit notes, re-issues)

    @property
    def net(self) -> float:
        return round(sum(l.net for l in self.lines), 2)

    @property
    def vat(self) -> float:
        return round(self.net * self.vat_rate, 2)

    @property
    def total(self) -> float:
        return round(self.net + self.vat, 2)


@dataclass
class Email:
    msg_id: str
    day: int
    from_name: str
    from_addr: str
    to_addr: str
    subject: str
    body: str
    attachment_doc_ids: list[str] = field(default_factory=list)


@dataclass
class GroundTruth:
    is_attack: bool = False
    family: Optional[str] = None          # "A1".."A9" for attacks
    lookalike_of: Optional[str] = None    # family whose benign twin this is
    payee_supplier_id: Optional[str] = None
    legit_value: float = 0.0              # value that a correct process pays for this item (AED, gross)
    attacker_iban: Optional[str] = None
    attacker_goal: str = ""
    expected_action: str = "record"       # pay | short_pay | hold | reject | escalate | record
    template_id: str = ""
    split: str = "dev"
    linked_item: Optional[str] = None     # e.g. the original invoice a duplicate copies
    genuine_new_iban: Optional[str] = None  # benign bank change: new account truly owned


@dataclass
class InboxItem:
    item_id: str
    day: int
    kind: str          # invoice | credit_note | reissue | bank_change | onboarding | reminder | statement | query
    channel: str       # pdf | ubl | email
    email: Optional[Email]
    doc: Optional[Document]
    truth: GroundTruth

    def to_public_dict(self) -> dict:
        d = {"item_id": self.item_id, "day": self.day, "kind_hint": None, "channel": self.channel}
        if self.email is not None:
            d["email"] = asdict(self.email)
        if self.doc is not None:
            d["doc"] = asdict(self.doc)
        return d


@dataclass
class World:
    seed: int
    start: date
    n_days: int
    suppliers: dict[str, Supplier]
    employees: list[Employee]
    pos: dict[str, PurchaseOrder]
    receipts: list[GoodsReceipt]
    items: list[InboxItem]
    account_owner: dict[str, str]          # IBAN -> owner ("SUP-xxxx" or "ATTACKER")
    pending_suppliers: dict[str, Supplier] = field(default_factory=dict)  # genuine/fake onboarding
    org_name: str = "Meridian Components Trading LLC"
    org_domain: str = "meridian-components.example"
    org_trn: str = "100000000000001"
    split: str = "dev"

    def day_items(self, day: int) -> list[InboxItem]:
        return [it for it in self.items if it.day == day]

    def receipts_by_day(self, day: int) -> list[GoodsReceipt]:
        return [r for r in self.receipts if r.day == day]
