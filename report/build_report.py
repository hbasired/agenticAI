"""Build the interim report (DOCX + PDF) from scratch in the proposal's format.

  python report/build_report.py

Two passes: the first build is rendered to PDF to find the page of every heading; the
second build fills the contents page with those page numbers, as in the proposal.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from docx import Document

from references.bibliography import new_references
from report import content_a, content_b, content_c, content_d
from report.docxlib import Report
from report.results import load

PROPOSAL = os.path.join(ROOT, "Segregation_of_Duties_for_AI_Agents_Research_Proposal_Hemanth.docx")
OUT_DIR = os.path.join(ROOT, "report", "output")
OUT = os.path.join(OUT_DIR, "Segregation_of_Duties_for_AI_Agents_Interim_Report_Hemanth.docx")
SOFFICE = "/root/.claude/skills/synced/be1d1098-88e4-4aa3-b98f-df7f430e64b5_c2bb9e6c-5e65-4d7f-93b0-3f6134b5cda3/docx/scripts/office/soffice.py"


def original_references() -> dict[int, str]:
    doc = Document(PROPOSAL)
    refs, on = {}, False
    for p in doc.paragraphs:
        t = p.text.strip()
        if p.style.name.startswith("Heading") and t == "References":
            on = True
            continue
        if on:
            m = re.match(r"^\[(\d+)\]\s*(.*)$", t, re.S)
            if m:
                refs[int(m.group(1))] = " ".join(m.group(2).split())
    assert len(refs) == 52, len(refs)
    return refs


class Cites:
    def __init__(self):
        self.orig = original_references()
        self.new = dict(new_references())
        self.num: dict[str, int] = {}
        self.next = 53
        self.unknown: set[str] = set()

    def n(self, key: str) -> int:
        key = key.strip()
        if key.isdigit():
            assert int(key) in self.orig, key
            return int(key)
        if key not in self.new:
            self.unknown.add(key)
            return 0
        if key not in self.num:
            self.num[key] = self.next
            self.next += 1
        return self.num[key]

    def fmt(self, text: str) -> str:
        return re.sub(r"\{c:([^}]+)\}", lambda m: ", ".join(f"[{self.n(k)}]" for k in m.group(1).split(",")), text)


def build(pages: dict[str, int] | None, V, prev_labels: dict | None = None) -> tuple[Report, Cites]:
    cites = Cites()
    R = Report(PROPOSAL)
    R.prev_labels = prev_labels or {}
    orig_rich = R._rich
    R._rich = lambda p, text, **kw: orig_rich(p, R.resolve_refs(cites.fmt(text)), **kw)
    content_a.front(R, V)
    content_a.section1(R, V)
    content_a.section2(R, V)
    content_a.section3(R, V)
    content_a.section4(R, V)
    content_b.section5(R, V)
    content_c.section6(R, V)
    content_c.section7(R, V)
    content_d.section8(R, V)
    content_d.section9(R, V)
    content_d.section10(R, V)
    content_d.section11(R, V)
    content_d.section12(R, V)
    content_d.section13(R, V)
    content_d.appendix_a(R, V)
    content_d.appendix_b(R, V)
    R.h1("References")
    for n in range(1, 53):
        R.reference(n, cites.orig[n])
    for key, n in sorted(cites.num.items(), key=lambda kv: kv[1]):
        R.reference(n, cites.new[key])
    R.fill_contents(pages or {})
    return R, cites


def render_pdf(docx_path: str) -> str:
    subprocess.run([sys.executable, SOFFICE, "--headless", "--convert-to", "pdf", "--outdir", os.path.dirname(docx_path),
                    docx_path], check=True, capture_output=True)
    return docx_path[:-5] + ".pdf"


def heading_pages(pdf: str, entries) -> dict[str, int]:
    n_pages = int(re.search(r"Pages:\s+(\d+)", subprocess.run(["pdfinfo", pdf], capture_output=True, text=True).stdout).group(1))
    texts = []
    for i in range(1, n_pages + 1):
        t = subprocess.run(["pdftotext", "-f", str(i), "-l", str(i), "-layout", pdf, "-"], capture_output=True, text=True).stdout
        texts.append([" ".join(line.split()) for line in t.splitlines()])
    pages = {}
    for lvl, text, bm in entries:
        hits = [i + 1 for i, lines in enumerate(texts) if any(l == text or (l.startswith(text) and not re.search(r"\d+$", l))
                                                               for l in lines)]
        if not hits:
            hits = [i + 1 for i, lines in enumerate(texts) if any(l.startswith(text) for l in lines)]
        if hits:
            pages[bm] = hits[0] if text in ("Abstract", "Keywords") else hits[-1]
    return pages


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    V = load()
    R, cites = build(None, V)
    if cites.unknown:
        raise SystemExit(f"unknown citation keys: {sorted(cites.unknown)}")
    uncited = sorted(set(cites.new) - set(cites.num))
    if uncited:
        raise SystemExit(f"{len(uncited)} new references are never cited: {uncited}")
    R.save(OUT)
    pages = heading_pages(render_pdf(OUT), R.toc_entries)
    R2, _ = build(pages, V, prev_labels=R.labels)
    R2.save(OUT)
    subprocess.run(["zip", "-q", "-d", OUT, "*/"], capture_output=True)
    pdf = render_pdf(OUT)
    print(f"built {OUT} and {pdf}; references: {52 + len(cites.num)} ({len(cites.num)} new); "
          f"figures {R2.fig_n}, tables {R2.tab_n}")


if __name__ == "__main__":
    main()
