"""Agent-facing data types: typed proposals, actions and intents.

An *intent* is what an agent wants to happen for one inbox item. Whether any of it
happens is decided by the defence configuration (``sodbench.defences``), never by the
agent. A *proposal* is the typed, schema-conforming output of a maker session in the
Control-Grounded Agent Architecture; each field carries a provenance tag.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

PROVENANCE_DOCUMENT = "document"   # copied from untrusted supplier content
PROVENANCE_MASTER = "master"       # read from verified master data
PROVENANCE_AGENT = "agent"         # produced by the model itself


@dataclass
class ProposalLine:
    line_no: int
    qty: float
    unit_price: float


@dataclass
class Proposal:
    item_id: str
    doc_kind: str                       # invoice | credit_note | reissue | bank_change | onboarding | other
    supplier_id: Optional[str] = None
    supplier_name: str = ""
    invoice_number: str = ""
    po_ref: str = ""
    lines: list[ProposalLine] = field(default_factory=list)
    total: float = 0.0
    iban: Optional[str] = None          # beneficiary as stated in the item (untrusted provenance)
    requested_action: str = "record"    # pay | hold | escalate | reject | bank_change | onboard | record
    bank_change_iban: Optional[str] = None
    claims_verified: bool = False       # the content asserts that verification already happened
    instruction_flag: bool = False      # maker noticed instruction-like text aimed at automation
    urgency_flag: bool = False
    billing_reference: str = ""
    reasons: list[str] = field(default_factory=list)
    provenance: dict[str, str] = field(default_factory=dict)
    confidence: float = 1.0


@dataclass
class Action:
    kind: str                           # pay | update_bank | raise_ticket | onboard | escalate | hold | reject | note | record
    args: dict = field(default_factory=dict)


@dataclass
class Intent:
    item_id: str
    actions: list[Action] = field(default_factory=list)
    proposal: Optional[Proposal] = None
    suspicion: float = 0.0              # the agent's own risk estimate in [0, 1]
    deceived: bool = False              # behavioural agents only: did it pursue the attacker goal?
    summary: str = ""                   # free-text hand-off (naive LLM segregation, D7)
    tokens: int = 0
    seconds: float = 0.0
    raw: str = ""
