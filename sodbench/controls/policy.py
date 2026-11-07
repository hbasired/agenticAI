"""Policy pack: the configuration of the controls-as-code checker.

Every number here is a business parameter a finance team would set, so it can be
loaded from YAML, versioned and audited like any other control configuration.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

import yaml


@dataclass
class PolicyPack:
    # three-way match
    price_tolerance_pct: float = 0.02         # invoice unit price may exceed PO price by up to 2 %
    qty_tolerance_pct: float = 0.0            # never pay for more than was received
    total_tolerance_abs: float = 1.0          # rounding allowance per invoice (AED)
    short_pay: bool = True                    # pay the matched part, hold the remainder
    # duplicates
    duplicate_window_days: int = 60
    duplicate_amount_rel: float = 0.01
    # approval matrix (maker-checker above limits)
    human_release_threshold: float = 250_000.0  # payments above need human release
    non_po_auto_limit: float = 2_000.0          # low-value non-PO invoices auto-approved
    non_po_approval_limit: float = 25_000.0     # above auto limit: human approval; above this: reject
    non_po_standing_limit: float = 60_000.0     # recurring utility contracts without a PO
    non_po_categories: tuple = ("utilities", "it_services", "marketing", "facilities")
    # vendor-master change control
    cooling_off_days: int = 3
    require_callback: bool = True
    vop_block_on_no_match: bool = True
    # supplier onboarding
    first_payment_hold: bool = True
    # data-flow control
    provenance_rule: bool = True              # beneficiary only from verified master data
    # payment run
    payment_weekday: int = 3                  # Thursday
    extra: dict = field(default_factory=dict)

    def to_yaml(self) -> str:
        d = asdict(self)
        d["non_po_categories"] = list(self.non_po_categories)
        return yaml.safe_dump(d, sort_keys=False)

    @classmethod
    def from_yaml(cls, text: str) -> "PolicyPack":
        d = yaml.safe_load(text) or {}
        if "non_po_categories" in d:
            d["non_po_categories"] = tuple(d["non_po_categories"])
        return cls(**d)
