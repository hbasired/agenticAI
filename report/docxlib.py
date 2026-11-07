"""Builder for the interim report that reproduces the proposal's formatting exactly.

The report is written from scratch. To keep fonts, sizes, heading styles, list
numbering, page set-up and footer identical to the proposal, the proposal file is used
only as a *style template*: its body is emptied and every paragraph and table of the
report is created anew with the same style ids and direct formatting (see
docs/formatting_spec.md).
"""
from __future__ import annotations

import copy
import re

from docx import Document
from docx.enum.text import WD_BREAK
from docx.opc.constants import RELATIONSHIP_TYPE as RT
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"


def _el(tag, **attrs):
    e = OxmlElement(tag)
    for k, v in attrs.items():
        e.set(qn(k), str(v))
    return e


class Report:
    def __init__(self, template: str):
        self.doc = Document(template)
        body = self.doc.element.body
        for child in list(body):
            if child.tag != qn("w:sectPr"):
                body.remove(child)
        self.body = body
        self.sect = body.find(qn("w:sectPr"))
        for section in self.doc.sections:          # footer text inherited from the template
            for part in (section.footer, section.first_page_footer, section.even_page_footer):
                for t in part._element.iter(qn("w:t")):
                    if t.text and "Research Proposal" in t.text:
                        t.text = t.text.replace("Research Proposal", "Interim Report")
        self.toc_entries: list[tuple[int, str, str]] = []   # (level, text, bookmark)
        self._bm = 0
        self.fig_n = 0
        self.tab_n = 0
        self.labels: dict[str, int] = {}
        self.prev_labels: dict[str, int] = {}

    # ------------------------------------------------------------------ low level
    def _p(self):
        p = _el("w:p")
        self.sect.addprevious(p)
        return p

    @staticmethod
    def _ppr(p, style=None, jc=None, before=None, after=None, line=None, ind_left=None, ind_right=None,
             hanging=None, keep_next=False, tab=None, num=None):
        ppr = _el("w:pPr")
        if style:
            ppr.append(_el("w:pStyle", **{"w:val": style}))
        if keep_next:
            ppr.append(_el("w:keepNext"))
        if num is not None:
            numpr = _el("w:numPr")
            numpr.append(_el("w:ilvl", **{"w:val": 0}))
            numpr.append(_el("w:numId", **{"w:val": num}))
            ppr.append(numpr)
        if tab is not None:
            tabs = _el("w:tabs")
            tabs.append(_el("w:tab", **{"w:val": "left", "w:pos": tab}))
            ppr.append(tabs)
        if before is not None or after is not None or line is not None:
            sp = _el("w:spacing")
            if before is not None:
                sp.set(qn("w:before"), str(before))
            if after is not None:
                sp.set(qn("w:after"), str(after))
            if line is not None:
                sp.set(qn("w:line"), str(line))
                sp.set(qn("w:lineRule"), "auto")
            ppr.append(sp)
        if ind_left is not None or ind_right is not None or hanging is not None:
            ind = _el("w:ind")
            if ind_left is not None:
                ind.set(qn("w:left"), str(ind_left))
            if ind_right is not None:
                ind.set(qn("w:right"), str(ind_right))
            if hanging is not None:
                ind.set(qn("w:hanging"), str(hanging))
            ppr.append(ind)
        if jc:
            ppr.append(_el("w:jc", **{"w:val": jc}))
        if len(ppr):
            p.append(ppr)
        return ppr

    @staticmethod
    def _run(p, text, b=False, i=False, sz=None, font=None, color=None, u=False, sub=False, sup=False):
        r = _el("w:r")
        rpr = _el("w:rPr")
        if font:
            rpr.append(_el("w:rFonts", **{"w:ascii": font, "w:eastAsia": font, "w:hAnsi": font, "w:cs": font}))
        if b:
            rpr.append(_el("w:b"))
            rpr.append(_el("w:bCs"))
        if i:
            rpr.append(_el("w:i"))
            rpr.append(_el("w:iCs"))
        if color:
            rpr.append(_el("w:color", **{"w:val": color}))
        if sz:
            rpr.append(_el("w:sz", **{"w:val": sz}))
            rpr.append(_el("w:szCs", **{"w:val": sz}))
        if u:
            rpr.append(_el("w:u", **{"w:val": "single"}))
        if sub or sup:
            rpr.append(_el("w:vertAlign", **{"w:val": "subscript" if sub else "superscript"}))
        if len(rpr):
            r.append(rpr)
        parts = text.split("\t")
        for k, part in enumerate(parts):
            if k:
                r.append(_el("w:tab"))
            t = _el("w:t")
            t.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
            t.text = part
            r.append(t)
        p.append(r)
        return r

    def _rich(self, p, text, sz=None, base_b=False, base_i=False):
        """Inline markup: **bold**, *italic*, _{sub}, ^{sup}."""
        for tok in re.split(r"(\*\*[^*]+\*\*|\*[^*]+\*|_\{[^}]+\}|\^\{[^}]+\})", text):
            if not tok:
                continue
            if tok.startswith("**"):
                self._run(p, tok[2:-2], b=True, i=base_i, sz=sz)
            elif tok.startswith("*"):
                self._run(p, tok[1:-1], i=True, b=base_b, sz=sz)
            elif tok.startswith("_{"):
                self._run(p, tok[2:-1], sub=True, sz=sz, i=base_i)
            elif tok.startswith("^{"):
                self._run(p, tok[2:-1], sup=True, sz=sz, i=base_i)
            else:
                self._run(p, tok, b=base_b, i=base_i, sz=sz)

    def page_break_in(self, p):
        r = _el("w:r")
        br = _el("w:br", **{"w:type": "page"})
        r.append(br)
        p.append(r)

    def page_break(self):
        p = self._p()
        self.page_break_in(p)

    # ------------------------------------------------------------------ title page
    def title_page(self, title, subtitle, doctype, note, meta_lines, honesty_text):
        p = self._p(); self._ppr(p, jc="center", before=1300, after=160); self._run(p, title, b=True, sz=40)
        p = self._p(); self._ppr(p, jc="center", after=160); self._run(p, subtitle, b=True, sz=28)
        p = self._p(); self._ppr(p, jc="center"); self._run(p, doctype, b=True, sz=24)
        p = self._p(); self._ppr(p, jc="center", after=420); self._run(p, note, i=True, sz=19)
        for line in meta_lines:
            p = self._p(); self._ppr(p, jc="center", after=70); self._run(p, line)
        p = self._p(); self._ppr(p, jc="center", before=520)
        self._run(p, "Honesty note", font="Calibri", color="1F3864", sz=26)
        for k, para in enumerate(honesty_text):
            p = self._p(); self._ppr(p, jc="center", after=0 if k == len(honesty_text) - 1 else 80, ind_left=360,
                                     ind_right=360)
            self._rich(p, para, sz=20)
            if k == len(honesty_text) - 1:
                self.page_break_in(p)

    # ------------------------------------------------------------------ headings and text
    def _bookmark(self, p, text):
        self._bm += 1
        name = f"_TocSec{self._bm:02d}"
        bs = _el("w:bookmarkStart", **{"w:id": self._bm, "w:name": name})
        be = _el("w:bookmarkEnd", **{"w:id": self._bm})
        ppr = p.find(qn("w:pPr"))
        if ppr is not None:
            ppr.addnext(bs)
        else:
            p.insert(0, bs)
        p.append(be)
        return name

    def h1(self, text, toc=True):
        p = self._p(); self._ppr(p, style="Heading1"); self._run(p, text)
        if toc:
            self.toc_entries.append((1, text, self._bookmark(p, text)))

    def h2(self, text, toc=True):
        p = self._p(); self._ppr(p, style="Heading2"); self._run(p, text)
        if toc:
            self.toc_entries.append((2, text, self._bookmark(p, text)))

    def para(self, text, after=None, jc=None):
        p = self._p()
        if after is not None or jc:
            self._ppr(p, after=after, jc=jc)
        self._rich(p, text)
        return p

    def rq(self, lead, text):
        p = self._p(); self._ppr(p, after=100, ind_left=360)
        self._run(p, lead, b=True)
        self._rich(p, " " + text)

    def bullet(self, text, lead=None):
        p = self._p(); self._ppr(p, style="ListParagraph", num=2, after=80)
        if lead:
            self._run(p, lead, b=True)
            self._rich(p, " " + text)
        else:
            self._rich(p, text)

    def equation(self, text):
        p = self._p(); self._ppr(p, jc="center", before=60)
        self._rich(p, text, base_i=True)

    def resolve_refs(self, text: str) -> str:
        return re.sub(r"\{ref:([^}]+)\}", lambda m: str(self.prev_labels.get(m.group(1), "?")), text)

    def figure(self, path, caption, width_in=6.5, label=None):
        p = self._p(); self._ppr(p, jc="center", before=120, after=0, line=240, keep_next=True)
        tmp = self.doc.add_paragraph()
        tmp.add_run().add_picture(path, width=Inches(width_in))
        for r in tmp._p.findall(qn("w:r")):
            p.append(r)
        tmp._p.getparent().remove(tmp._p)
        self.fig_n += 1
        if label:
            self.labels[label] = self.fig_n
        c = self._p(); self._ppr(c, jc="center", before=80, after=220)
        self._rich(c, f"Figure {self.fig_n}. {caption}", sz=20, base_i=True)
        return self.fig_n

    def table(self, header, rows, widths, caption, bold_last_row=False, label=None):
        assert abs(sum(widths) - 9360) <= 2, sum(widths)
        tbl = _el("w:tbl")
        tpr = _el("w:tblPr")
        tpr.append(_el("w:tblW", **{"w:w": 9360, "w:type": "dxa"}))
        borders = _el("w:tblBorders")
        for side in ("top", "left", "bottom", "right", "insideH", "insideV"):
            borders.append(_el(f"w:{side}", **{"w:val": "single", "w:sz": 4, "w:space": 0, "w:color": "A6A6A6"}))
        tpr.append(borders)
        mar = _el("w:tblCellMar")
        mar.append(_el("w:left", **{"w:w": 10, "w:type": "dxa"}))
        mar.append(_el("w:right", **{"w:w": 10, "w:type": "dxa"}))
        tpr.append(mar)
        tpr.append(_el("w:tblLook", **{"w:val": "0000", "w:firstRow": 0, "w:lastRow": 0, "w:firstColumn": 0,
                                       "w:lastColumn": 0, "w:noHBand": 0, "w:noVBand": 0}))
        tbl.append(tpr)
        grid = _el("w:tblGrid")
        for wdt in widths:
            grid.append(_el("w:gridCol", **{"w:w": wdt}))
        tbl.append(grid)

        def cell(text, wdt, head=False, bold=False):
            tc = _el("w:tc")
            tcpr = _el("w:tcPr")
            tcpr.append(_el("w:tcW", **{"w:w": wdt, "w:type": "dxa"}))
            if head:
                tcpr.append(_el("w:shd", **{"w:val": "clear", "w:color": "auto", "w:fill": "D9E2F3"}))
            m = _el("w:tcMar")
            for side, v in (("top", 50), ("left", 90), ("bottom", 50), ("right", 90)):
                m.append(_el(f"w:{side}", **{"w:w": v, "w:type": "dxa"}))
            tcpr.append(m)
            tc.append(tcpr)
            for k, line in enumerate(str(text).split("\n")):
                p = _el("w:p")
                self._ppr(p, after=0, line=240, keep_next=head)
                self._rich(p, line, sz=19, base_b=head or bold)
                tc.append(p)
            return tc

        tr = _el("w:tr")
        trpr = _el("w:trPr")
        trpr.append(_el("w:tblHeader"))
        tr.append(trpr)
        for h, wdt in zip(header, widths):
            tr.append(cell(h, wdt, head=True))
        tbl.append(tr)
        for k, row in enumerate(rows):
            tr = _el("w:tr")
            for v, wdt in zip(row, widths):
                tr.append(cell(v, wdt, bold=bold_last_row and k == len(rows) - 1))
            tbl.append(tr)
        self.sect.addprevious(tbl)
        self.tab_n += 1
        if label:
            self.labels[label] = self.tab_n
        c = self._p(); self._ppr(c, jc="center", before=80, after=220)
        self._rich(c, f"Table {self.tab_n}. {caption}", sz=20, base_i=True)
        return self.tab_n

    # ------------------------------------------------------------------ contents
    def contents_placeholder(self):
        p = self._p(); self._ppr(p, after=200)
        self._run(p, "Contents", font="Calibri", b=True, color="1F3864", sz=28)
        self._toc_anchor = self._p()      # TOC paragraphs are inserted before this marker later
        self.page_break_in(self._toc_anchor)

    def fill_contents(self, pages: dict[str, int]):
        anchor = self._toc_anchor
        first = True
        for k, (lvl, text, bm) in enumerate(self.toc_entries):
            p = _el("w:p")
            self._ppr(p, style="TOC1" if lvl == 1 else "TOC2")
            if first:
                r = _el("w:r"); r.append(_el("w:fldChar", **{"w:fldCharType": "begin"})); p.append(r)
                r = _el("w:r"); it = _el("w:instrText"); it.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
                it.text = ' TOC \\o "1-2" \\h \\z \\u '; r.append(it); p.append(r)
                r = _el("w:r"); r.append(_el("w:fldChar", **{"w:fldCharType": "separate"})); p.append(r)
                first = False
            hl = _el("w:hyperlink", **{"w:anchor": bm, "w:history": 1})
            self._run(hl, text)
            self._run(hl, "\t" + str(pages.get(bm, "")))
            p.append(hl)
            if k == len(self.toc_entries) - 1:
                r = _el("w:r"); r.append(_el("w:fldChar", **{"w:fldCharType": "end"})); p.append(r)
            anchor.addprevious(p)

    # ------------------------------------------------------------------ references
    def reference(self, n, text):
        p = self._p(); self._ppr(p, tab=560, after=90, line=252, ind_left=560, hanging=560)
        m = re.search(r"(https?://\S+?)([.,;)]?)$", text)
        if m:
            pre, url, tail = text[: m.start(1)], m.group(1), m.group(2)
            self._run(p, f"[{n}]\t{pre}", sz=20)
            rid = self.doc.part.relate_to(url, RT.HYPERLINK, is_external=True)
            hl = _el("w:hyperlink"); hl.set(qn("r:id"), rid)
            self._run(hl, url, sz=20, color="0563C1", u=True)
            p.append(hl)
            if tail:
                self._run(p, tail, sz=20)
        else:
            self._run(p, f"[{n}]\t{text}", sz=20)

    def save(self, path):
        self.doc.core_properties.title = "Segregation of Duties for AI Agents - Interim Report"
        self.doc.save(path)
