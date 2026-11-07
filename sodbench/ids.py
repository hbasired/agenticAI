"""Identifier utilities: IBANs, tax numbers, invoice numbers and look-alike domains.

All identifiers are synthetic. IBANs follow the ISO 13616 structure and are
checksum-valid (mod 97) but use bank codes in a range that SoD-Bench reserves for
fictitious banks; e-mail domains use the reserved ``.example`` top-level domain
(RFC 2606), so nothing generated here can route to a real party.
"""
from __future__ import annotations

import random
import re
import string

# Fictitious banks. Codes 9xx are used so that generated IBANs are unlikely to
# coincide with real UAE bank identifiers; names are invented.
FICTITIOUS_BANKS = {
    "901": "Corniche Commercial Bank",
    "902": "Dune Federal Bank",
    "903": "Pearl Coast Bank",
    "904": "Falcon Gate Bank",
    "905": "Oasis Merchant Bank",
    "906": "Saffron Reserve Bank",
    "907": "Harbour Light Bank",
    "908": "Mirage National Bank",
}
# Banks used by attackers in development vs held-out attack templates, so that a
# defence cannot learn "bank 9xx means fraud" from the development split.
ATTACKER_BANKS = {"dev": ["905", "906"], "heldout": ["907", "908"]}
SUPPLIER_BANKS = ["901", "902", "903", "904", "905", "906", "907", "908"]


def _iban_check_digits(country: str, bban: str) -> str:
    rearranged = bban + country + "00"
    numeric = "".join(str(int(ch, 36)) for ch in rearranged)
    return f"{98 - int(numeric) % 97:02d}"


def make_iban_ae(rng: random.Random, bank_code: str | None = None) -> str:
    """Return a checksum-valid, fictitious UAE-format IBAN (23 characters)."""
    bank_code = bank_code or rng.choice(SUPPLIER_BANKS)
    account = "".join(rng.choice(string.digits) for _ in range(16))
    bban = bank_code + account
    return "AE" + _iban_check_digits("AE", bban) + bban


def iban_is_valid(iban: str) -> bool:
    s = re.sub(r"\s+", "", iban or "").upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{10,30}", s):
        return False
    rearranged = s[4:] + s[:4]
    numeric = "".join(str(int(ch, 36)) for ch in rearranged)
    return int(numeric) % 97 == 1


def format_iban(iban: str) -> str:
    s = re.sub(r"\s+", "", iban)
    return " ".join(s[i:i + 4] for i in range(0, len(s), 4))


def normalise_iban(text: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", (text or "").upper())


IBAN_PATTERN = re.compile(r"\b([A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){3,7}(?:\s?[A-Z0-9]{1,3})?)\b")


def find_ibans(text: str) -> list[str]:
    """Return all checksum-valid IBANs mentioned in free text (normalised)."""
    out = []
    for m in IBAN_PATTERN.finditer((text or "").upper()):
        cand = normalise_iban(m.group(1))
        # try progressively shorter prefixes: free text may run digits together
        for length in range(len(cand), 14, -1):
            if iban_is_valid(cand[:length]):
                out.append(cand[:length])
                break
    return out


def bank_name_for(iban: str) -> str:
    code = normalise_iban(iban)[4:7]
    return FICTITIOUS_BANKS.get(code, "Unknown Bank")


def make_trn(rng: random.Random) -> str:
    """Synthetic 15-digit tax registration number with a Luhn check digit."""
    body = "100" + "".join(rng.choice(string.digits) for _ in range(11))
    return body + _luhn_digit(body)


def _luhn_digit(body: str) -> str:
    total = 0
    for i, ch in enumerate(reversed(body)):
        d = int(ch)
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return str((10 - total % 10) % 10)


INVOICE_STYLES = [
    "INV-{n:04d}", "INV{n:05d}", "{yy}/{n:04d}", "SI-{yy}-{n:05d}", "TI{n:06d}", "{pfx}-{yy}{n:04d}",
]


def invoice_number(style: str, n: int, year: int, prefix: str) -> str:
    return style.format(n=n, yy=str(year)[-2:], pfx=prefix)


def normalise_invoice_number(num: str) -> str:
    """Canonical form used by fuzzy duplicate detection."""
    s = re.sub(r"[^A-Z0-9]", "", (num or "").upper())
    s = re.sub(r"^(INV|SI|TI|INVOICE|NO)", "", s)
    s = s.lstrip("0")
    return s


def slugify(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "", name.lower())
    return s[:18] or "supplier"


def lookalike_domains(domain: str, rng: random.Random, split: str) -> list[str]:
    """Generate look-alike variants of ``name.example``.

    Development and held-out splits use disjoint transformation families so that
    held-out attacks contain look-alike patterns not seen during development.
    """
    base, _, tld = domain.partition(".")
    dev = [
        base.replace("o", "0", 1) if "o" in base else base + "s",
        base + "-ae",
        base.replace("l", "1", 1) if "l" in base else base + "co",
    ]
    held = [
        base[:-1] + base[-1] * 2,
        "accounts-" + base,
        base.replace("i", "l", 1) if "i" in base else base[::-1][:3] + base,
        base + "-billing",
    ]
    pool = dev if split == "dev" else held
    out = [p + "." + (tld or "example") for p in pool if p != base]
    rng.shuffle(out)
    return out


def domain_similarity(a: str, b: str) -> float:
    """Normalised similarity in [0, 1] between two domains (1 = identical)."""
    a, b = a.lower(), b.lower()
    if a == b:
        return 1.0
    # Levenshtein distance, small strings only
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    dist = prev[-1]
    return 1.0 - dist / max(len(a), len(b))
