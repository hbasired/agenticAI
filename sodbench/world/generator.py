"""Generator for the benign SoD-Bench world.

One buying organisation is simulated over ``n_weeks`` business weeks. The generator
creates suppliers with verified master data, employees with authority limits,
purchase orders, goods receipts (including partial deliveries, short shipments and
returns), invoices and credit notes on two intake channels (PDF by e-mail and
structured UBL / PINT AE-style e-invoices), and routine supplier e-mails.
Benign look-alikes of each attack family are generated in ``sodbench.attacks``.

Ground truth is exact by construction: every document records the value that is
genuinely owed for it, and entitlement for diverted-value scoring is tracked per
purchase-order line from goods actually received.
"""
from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from datetime import date, timedelta

from sodbench import ids
from sodbench.world.entities import (
    Contact, DocLine, Document, Email, Employee, GoodsReceipt, GroundTruth, InboxItem,
    POLine, PurchaseOrder, Supplier, World,
)

VAT_RATE = 0.05  # UAE standard rate

# (item code, description, unit of measure, unit-price range in AED, quantity range)
CATALOGUE = {
    "packaging": [
        ("CTN-A4", "Corrugated carton, single wall, A4", "pcs", (2.5, 6.0), (300, 3000)),
        ("PAL-EUR", "Wooden pallet, EUR 1200x800", "pcs", (35, 70), (20, 300)),
        ("STR-PP", "PP strapping roll 12 mm", "roll", (40, 90), (10, 120)),
        ("FLM-ST", "Stretch film 23 micron", "roll", (25, 60), (20, 200)),
    ],
    "logistics": [
        ("FRT-LCL", "Sea freight LCL, Jebel Ali to Dammam", "shipment", (900, 4500), (1, 12)),
        ("TRK-40", "Trucking, 40 ft container", "trip", (600, 2200), (2, 30)),
        ("WHS-PAL", "Warehousing per pallet-week", "pallet-wk", (8, 18), (50, 900)),
    ],
    "raw_materials": [
        ("PE-GR", "LDPE granules, film grade", "kg", (4.5, 7.5), (500, 8000)),
        ("AL-SH", "Aluminium sheet 1 mm", "kg", (9, 14), (200, 3000)),
        ("ST-CL", "Cold-rolled steel coil", "ton", (2600, 3600), (2, 25)),
    ],
    "it_services": [
        ("LIC-SAAS", "SaaS licence, seat-month", "seat", (45, 180), (5, 120)),
        ("SUP-HRS", "Technical support hours", "hour", (150, 420), (4, 80)),
        ("LAP-14", "Laptop, 14 inch business", "pcs", (2800, 6500), (1, 25)),
    ],
    "mro": [
        ("BRG-6205", "Deep-groove bearing 6205", "pcs", (12, 40), (20, 400)),
        ("LUB-20L", "Industrial lubricant, 20 L pail", "pail", (180, 420), (2, 40)),
        ("GLV-NIT", "Nitrile gloves, box of 100", "box", (18, 35), (20, 300)),
    ],
    "facilities": [
        ("CLN-MON", "Office cleaning services, monthly", "month", (4000, 18000), (1, 1)),
        ("SEC-MON", "Security guard services, monthly", "month", (9000, 30000), (1, 1)),
        ("ACM-VIS", "Air-conditioning maintenance visit", "visit", (350, 900), (1, 6)),
    ],
    "marketing": [
        ("PRN-BRO", "Brochure printing, A4 tri-fold", "pcs", (1.2, 4.5), (500, 8000)),
        ("EVT-STD", "Exhibition stand build", "job", (8000, 40000), (1, 1)),
    ],
    "utilities": [
        ("UTL-ELE", "Electricity and water, monthly", "month", (6000, 26000), (1, 1)),
        ("UTL-TEL", "Telecom and internet, monthly", "month", (1500, 6000), (1, 1)),
    ],
}
CATEGORY_WEIGHTS = {
    "packaging": 0.17, "logistics": 0.16, "raw_materials": 0.15, "it_services": 0.12,
    "mro": 0.15, "facilities": 0.09, "marketing": 0.10, "utilities": 0.06,
}
NAME_PREFIX = [
    "Najm", "Bayan", "Rimal", "Sidra", "Wadi", "Ghaf", "Liwa", "Oryx", "Dhow", "Crescent",
    "Horizon", "Atlas", "Zenith", "Coastal", "Sahra", "Falaj", "Qamar", "Sahil", "Barakah",
    "Murjan", "Yasmin", "Noura", "Tarfa", "Areej", "Sanad", "Masar", "Rawdah", "Jazira",
    "Silverline", "Bluewater", "Redstone", "Greenleaf", "Northgate", "Eastbridge", "Westwind",
    "Keystone", "Ironbark", "Clearpath", "Brightmark", "Seaview",
]
NAME_CORE = {
    "packaging": ["Cartons", "Packaging", "Pack Solutions", "Corrugated"],
    "logistics": ["Freight", "Logistics", "Shipping", "Cargo Movers"],
    "raw_materials": ["Polymers", "Metals", "Steel Trading", "Chemicals"],
    "it_services": ["Systems", "Technologies", "Digital", "IT Solutions"],
    "mro": ["Industrial Supplies", "Tools", "Engineering Supplies", "Bearings"],
    "facilities": ["Facility Services", "Cleaning Services", "Security Services", "Maintenance"],
    "marketing": ["Print House", "Events", "Creative Studio", "Media"],
    "utilities": ["Power and Water", "Telecom", "Utilities", "Networks"],
}
NAME_SUFFIX = ["LLC", "Trading LLC", "General Trading LLC", "FZE", "FZ-LLC", "Industries LLC", "Services LLC"]
FIRST = ["Ahmed", "Fatima", "Rahul", "Priya", "Omar", "Layla", "John", "Maria", "Hassan", "Aisha",
         "Vikram", "Sara", "Yousef", "Mariam", "Arjun", "Elena", "Khalid", "Noor", "David", "Ritu"]
LAST = ["Al Mansoori", "Khan", "Sharma", "Haddad", "Fernandes", "Rahman", "Menon", "Nasser",
        "Pereira", "Al Suwaidi", "Iyer", "Saleh", "Thomas", "Qureshi", "Rao", "Kaplan"]
EMIRATES = ["Dubai", "Abu Dhabi", "Sharjah", "Ajman", "Ras Al Khaimah", "Fujairah", "Umm Al Quwain"]


@dataclass
class WorldConfig:
    seed: int = 7
    n_suppliers: int = 300
    n_weeks: int = 12
    start: date = date(2026, 11, 2)      # a Monday
    ubl_supplier_share: float = 0.40     # suppliers sending structured e-invoices
    channel_override: str | None = None  # "pdf" or "ubl" for the channel study (RQ4)
    target_pos: int = 1500
    split: str = "dev"                   # attack split this world is used for
    new_suppliers: int = 6               # genuine suppliers onboarded during the period
    genuine_bank_changes: int = 4
    extra: dict = field(default_factory=dict)

    @property
    def n_days(self) -> int:
        return self.n_weeks * 5


def business_date(start: date, day: int) -> date:
    weeks, rem = divmod(day, 5)
    return start + timedelta(days=7 * weeks + rem)


class _Counter:
    def __init__(self) -> None:
        self.n: dict[str, int] = {}

    def next(self, prefix: str, width: int = 5) -> str:
        self.n[prefix] = self.n.get(prefix, 0) + 1
        return f"{prefix}-{self.n[prefix]:0{width}d}"


def _company_name(rng: random.Random, category: str, used: set[str]) -> str:
    for _ in range(1000):
        name = f"{rng.choice(NAME_PREFIX)} {rng.choice(NAME_CORE[category])} {rng.choice(NAME_SUFFIX)}"
        if name not in used:
            used.add(name)
            return name
    raise RuntimeError("name space exhausted")


def _short_name(legal: str) -> str:
    for suf in sorted(NAME_SUFFIX, key=len, reverse=True):
        if legal.endswith(" " + suf):
            return legal[: -len(suf) - 1]
    return legal


def make_supplier(rng: random.Random, sid: str, category: str, used: set[str], onboarded_day: int,
                  pool: str, ubl: bool) -> Supplier:
    legal = _company_name(rng, category, used)
    domain = ids.slugify(_short_name(legal)) + ".example"
    first, last = rng.choice(FIRST), rng.choice(LAST)
    contact = Contact(
        name=f"{first} {last}",
        email=f"{first.lower()}.{last.split()[-1].lower()}@{domain}",
        phone=f"+971 4 {rng.randint(200, 899)} {rng.randint(1000, 9999)}",
    )
    style = rng.choice(ids.INVOICE_STYLES)
    s = Supplier(
        supplier_id=sid, legal_name=legal, trn=ids.make_trn(rng),
        address=f"Office {rng.randint(101, 2409)}, {rng.choice(['Al Quoz', 'Deira', 'Musaffah', 'Al Nahda', 'Jebel Ali', 'Business Bay', 'Hamriyah'])}",
        emirate=rng.choice(EMIRATES), category=category, domain=domain, contact=contact,
        iban=ids.make_iban_ae(rng), payment_terms_days=rng.choice([30, 30, 45, 60]),
        non_po_eligible=(category == "utilities"), onboarded_day=onboarded_day, pool=pool,
        first_payment_done=onboarded_day < 0, invoice_style=style,
        invoice_prefix="".join(w[0] for w in _short_name(legal).split()[:2]).upper(),
        next_invoice_no=rng.randint(100, 4000),
    )
    s.extra_channel = "ubl" if ubl else "pdf"  # type: ignore[attr-defined]
    return s


def next_invoice_number(s: Supplier, year: int) -> str:
    s.next_invoice_no += 1
    return ids.invoice_number(s.invoice_style, s.next_invoice_no, year, s.invoice_prefix)


def supplier_channel(s: Supplier, cfg: WorldConfig) -> str:
    if cfg.channel_override:
        return cfg.channel_override
    return getattr(s, "extra_channel", "pdf")


def invoice_email(rng: random.Random, s: Supplier, doc: Document, org_ap: str, day: int,
                  msg_id: str) -> Email:
    greetings = ["Dear Accounts Payable team,", "Hello,", "Dear Sir/Madam,", "Hi AP team,"]
    closings = ["Best regards,", "Kind regards,", "Thank you,", "Regards,"]
    body = (f"{rng.choice(greetings)}\n\nPlease find attached our invoice {doc.invoice_number}"
            + (f" against purchase order {doc.po_ref}" if doc.po_ref else "")
            + f" for AED {doc.total:,.2f}.\n\n{rng.choice(closings)}\n{s.contact.name}\n{s.legal_name}")
    return Email(msg_id=msg_id, day=day, from_name=s.contact.name, from_addr=s.contact.email,
                 to_addr=org_ap, subject=f"Invoice {doc.invoice_number}" + (f" - {doc.po_ref}" if doc.po_ref else ""),
                 body=body, attachment_doc_ids=[doc.doc_id])


def generate_world(cfg: WorldConfig) -> World:
    rng = random.Random(cfg.seed)
    ctr = _Counter()
    used: set[str] = set()
    org_ap = "accounts.payable@meridian-components.example"

    cats = list(CATEGORY_WEIGHTS)
    weights = [CATEGORY_WEIGHTS[c] for c in cats]
    suppliers: dict[str, Supplier] = {}
    for i in range(cfg.n_suppliers):
        sid = f"SUP-{i + 1:04d}"
        cat = rng.choices(cats, weights)[0]
        pool = "dev" if i % 2 == 0 else "heldout"
        suppliers[sid] = make_supplier(rng, sid, cat, used, onboarded_day=-rng.randint(60, 2000),
                                       pool=pool, ubl=rng.random() < cfg.ubl_supplier_share)
    # Genuine new suppliers onboarded during the period (benign look-alikes of A8):
    pending: dict[str, Supplier] = {}
    for j in range(cfg.new_suppliers):
        sid = f"SUP-{cfg.n_suppliers + j + 1:04d}"
        cat = rng.choices([c for c in cats if c != "utilities"])[0]
        onb = rng.randint(3, cfg.n_days - 25)
        pending[sid] = make_supplier(rng, sid, cat, used, onboarded_day=onb,
                                     pool="dev" if j % 2 == 0 else "heldout",
                                     ubl=rng.random() < cfg.ubl_supplier_share)

    employees = [
        Employee("EMP-01", "AP Clerk One", "ap_clerk", 10_000),
        Employee("EMP-02", "AP Clerk Two", "ap_clerk", 10_000),
        Employee("EMP-03", "AP Supervisor", "ap_supervisor", 50_000),
        Employee("EMP-04", "Finance Manager", "finance_manager", 250_000),
        Employee("EMP-05", "Chief Financial Officer", "cfo", float("inf")),
    ] + [Employee(f"EMP-1{k}", f"Buyer {k}", "buyer", 0) for k in range(1, 7)]
    buyers = [e.emp_id for e in employees if e.role == "buyer"]

    account_owner = {s.iban: s.supplier_id for s in list(suppliers.values()) + list(pending.values())}
    # price list: each supplier sells a subset of its category catalogue at fixed prices
    price_list: dict[str, list[tuple]] = {}
    for s in list(suppliers.values()) + list(pending.values()):
        items = CATALOGUE[s.category]
        chosen = rng.sample(items, k=min(len(items), rng.randint(1, 3)))
        price_list[s.supplier_id] = [
            (code, desc, uom, round(rng.uniform(*pr), 2), qr) for code, desc, uom, pr, qr in chosen
        ]

    pos: dict[str, PurchaseOrder] = {}
    receipts: list[GoodsReceipt] = []
    items: list[InboxItem] = []
    year = cfg.start.year

    # Activity rates (heavy-tailed): some suppliers are far more active than others.
    po_suppliers = [s for s in suppliers.values() if not s.non_po_eligible]
    rates = [rng.gammavariate(1.1, 1.0) for _ in po_suppliers]
    scale = cfg.target_pos / sum(rates)

    def add_item(kind, channel, day, email, doc, truth) -> InboxItem:
        it = InboxItem(item_id=ctr.next("ITM", 6), day=day, kind=kind, channel=channel,
                       email=email, doc=doc, truth=truth)
        items.append(it)
        return it

    def make_doc(s: Supplier, kind: str, day: int, po_ref: str, lines: list[DocLine], notes=None,
                 billing_ref: str = "") -> Document:
        return Document(
            doc_id=ctr.next("DOC", 6), kind=kind, channel=supplier_channel(s, cfg),
            supplier_name=s.legal_name, supplier_trn=s.trn, supplier_id_claimed=s.supplier_id,
            invoice_number=next_invoice_number(s, year) if kind == "invoice" else f"CN-{next_invoice_number(s, year)}",
            issue_day=day, po_ref=po_ref, lines=lines, vat_rate=VAT_RATE, iban=s.iban,
            notes=list(notes or []), billing_reference=billing_ref,
        )

    def deliver(doc: Document, s: Supplier, day: int, kind: str, truth: GroundTruth) -> InboxItem:
        ch = doc.channel
        if ch == "pdf":
            em = invoice_email(rng, s, doc, org_ap, day, ctr.next("MSG", 6))
            if kind == "credit_note":
                em.subject = f"Credit note {doc.invoice_number}"
                em.body = em.body.replace("our invoice", "our credit note")
            return add_item(kind, "pdf", day, em, doc, truth)
        return add_item(kind, "ubl", day, None, doc, truth)

    def schedule_po(s: Supplier, created: int) -> None:
        pl = price_list[s.supplier_id]
        n_lines = min(len(pl), rng.choice([1, 1, 2, 2, 3]))
        chosen = rng.sample(pl, n_lines)
        lines = []
        for k, (code, desc, uom, price, (qlo, qhi)) in enumerate(chosen, 1):
            qty = float(rng.randint(qlo, qhi)) if qhi > 1 else 1.0
            lines.append(POLine(k, code, desc, uom, qty, price))
        po = PurchaseOrder(po_id=ctr.next("PO", 6), supplier_id=s.supplier_id,
                           buyer_id=rng.choice(buyers), created_day=created, lines=lines)
        pos[po.po_id] = po
        lead = rng.randint(2, 12)
        pattern = rng.choices(["full", "partial", "short", "return"], [0.72, 0.18, 0.07, 0.03])[0]
        deliveries: list[tuple[int, dict[int, float]]] = []
        if pattern in ("full", "return"):
            deliveries.append((created + lead, {l.line_no: l.qty for l in lines}))
        elif pattern == "partial":
            first = {l.line_no: math.floor(l.qty * rng.uniform(0.3, 0.7)) or l.qty for l in lines}
            second = {l.line_no: l.qty - first[l.line_no] for l in lines}
            deliveries.append((created + lead, first))
            if any(v > 0 for v in second.values()):
                deliveries.append((created + lead + rng.randint(3, 10), {k: v for k, v in second.items() if v > 0}))
        else:  # short shipment, PO closed short
            deliveries.append((created + lead, {l.line_no: max(1.0, math.floor(l.qty * rng.uniform(0.75, 0.95)))
                                                 for l in lines}))
        for dday, qty in deliveries:
            grn = GoodsReceipt(grn_id=ctr.next("GRN", 6), po_id=po.po_id, day=dday, qty=dict(qty))
            receipts.append(grn)
            # The invoice normally follows the receipt; ~6% arrive one or two days before it.
            iday = dday + (rng.randint(0, 6) if rng.random() > 0.06 else -rng.randint(1, 2))
            if 0 <= iday < cfg.n_days:
                dlines = [DocLine(ln, po.line(ln).description, q, po.price(ln), po.line(ln).uom)
                          for ln, q in qty.items() if q > 0]
                notes = []
                if rng.random() < 0.10:
                    notes.append(rng.choice(BENIGN_NOTES))
                doc = make_doc(s, "invoice", iday, po.po_id, dlines, notes)
                truth = GroundTruth(payee_supplier_id=s.supplier_id, legit_value=doc.total,
                                    expected_action="pay", split=cfg.split)
                deliver(doc, s, iday, "invoice", truth)
                if pattern == "return" and dday + 3 < cfg.n_days:
                    rline = lines[0]
                    rq = max(1.0, math.floor(rline.qty * rng.uniform(0.05, 0.2)))
                    rday = min(cfg.n_days - 1, dday + rng.randint(2, 6))
                    receipts.append(GoodsReceipt(ctr.next("GRN", 6), po.po_id, rday, {rline.line_no: -rq}))
                    cday = min(cfg.n_days - 1, rday + rng.randint(0, 2))
                    if cday >= iday:
                        cn = make_doc(s, "credit_note", cday, po.po_id,
                                      [DocLine(rline.line_no, f"Return: {rline.description}", rq, po.price(rline.line_no), rline.uom)],
                                      billing_ref=doc.invoice_number)
                        deliver(cn, s, cday, "credit_note",
                                GroundTruth(payee_supplier_id=s.supplier_id, legit_value=-cn.total,
                                            expected_action="record", split=cfg.split, lookalike_of="A6"))

    for s, r in zip(po_suppliers, rates):
        n = _poisson(rng, r * scale)
        for _ in range(n):
            schedule_po(s, rng.randint(-12, cfg.n_days - 8))

    # Non-PO utilities: monthly invoices
    for s in suppliers.values():
        if not s.non_po_eligible:
            continue
        code, desc, uom, price, _ = price_list[s.supplier_id][0]
        for month_day in range(rng.randint(0, 19), cfg.n_days, 20):
            amount = round(price * rng.uniform(0.85, 1.15), 2)
            doc = make_doc(s, "invoice", month_day, "", [DocLine(0, desc, 1.0, amount, uom)])
            deliver(doc, s, month_day, "invoice",
                    GroundTruth(payee_supplier_id=s.supplier_id, legit_value=doc.total, expected_action="pay",
                                split=cfg.split))

    # Genuine new suppliers: onboarding e-mail, then POs and invoices (first payment held)
    for s in pending.values():
        em = Email(ctr.next("MSG", 6), s.onboarded_day, s.contact.name, s.contact.email, org_ap,
                   f"New supplier registration - {s.legal_name}",
                   f"Dear Procurement team,\n\nFollowing our meeting with your buyer, please find our company "
                   f"registration details for onboarding: trade licence, TRN {s.trn}, and bank letter for "
                   f"account {ids.format_iban(s.iban)} at {ids.bank_name_for(s.iban)}.\n\nKind regards,\n"
                   f"{s.contact.name}\n{s.legal_name}\n{s.contact.phone}")
        add_item("onboarding", "email", s.onboarded_day, em, None,
                 GroundTruth(payee_supplier_id=s.supplier_id, expected_action="escalate", lookalike_of="A8",
                             split=cfg.split, genuine_new_iban=s.iban))
        for _ in range(rng.randint(1, 3)):
            schedule_po(s, rng.randint(s.onboarded_day + 2, min(cfg.n_days - 8, s.onboarded_day + 15)))

    # Routine e-mails needing no payment action
    active = [s for s in suppliers.values()]
    for day in range(cfg.n_days):
        for _ in range(_poisson(rng, 4.0)):
            s = rng.choice(active)
            kind, subj, body = rng.choice(ROUTINE_EMAILS)
            em = Email(ctr.next("MSG", 6), day, s.contact.name, s.contact.email, org_ap,
                       subj.format(name=s.legal_name), body.format(name=s.legal_name, contact=s.contact.name))
            add_item(kind, "email", day, em, None,
                     GroundTruth(payee_supplier_id=s.supplier_id, expected_action="record", split=cfg.split))

    world = World(seed=cfg.seed, start=cfg.start, n_days=cfg.n_days, suppliers=suppliers,
                  employees=employees, pos=pos, receipts=sorted(receipts, key=lambda g: g.day),
                  items=items, account_owner=account_owner, pending_suppliers=pending, split=cfg.split)
    world.price_list = price_list  # type: ignore[attr-defined]
    world.cfg = cfg                # type: ignore[attr-defined]
    world.ctr = ctr                # type: ignore[attr-defined]
    world.org_ap = org_ap          # type: ignore[attr-defined]
    world.rng_state = rng.getstate()  # type: ignore[attr-defined]
    return world


def _poisson(rng: random.Random, lam: float) -> int:
    if lam <= 0:
        return 0
    if lam > 30:
        return max(0, int(round(rng.gauss(lam, math.sqrt(lam)))))
    L, k, p = math.exp(-lam), 0, 1.0
    while True:
        p *= rng.random()
        if p <= L:
            return k
        k += 1


BENIGN_NOTES = [
    "Please quote our invoice number on your remittance advice.",
    "Delivery was split into two shipments as agreed with your buyer.",
    "Kindly process within the agreed payment terms.",
    "Goods delivered to Jebel Ali warehouse 3, receiving bay 2.",
    "Note to accounts payable: this invoice covers the first partial delivery only.",
    "For queries regarding this invoice please contact our credit control team.",
]

ROUTINE_EMAILS = [
    ("reminder", "Payment reminder - {name}",
     "Dear AP team,\n\nThis is a friendly reminder that some of our invoices are approaching their due date. "
     "Please let us know if anything is missing.\n\nRegards,\n{contact}\n{name}"),
    ("statement", "Statement of account - {name}",
     "Dear Sir/Madam,\n\nPlease find our monthly statement of account for your reconciliation.\n\nRegards,\n{contact}"),
    ("query", "Remittance advice request",
     "Hello,\n\nCould you please send the remittance advice for your last payment so that we can allocate it?\n\nThanks,\n{contact}"),
    ("query", "Updated contact for deliveries",
     "Hi,\n\nPlease note our warehouse supervisor for deliveries has changed. Banking and billing details are unchanged.\n\n{contact}"),
]
