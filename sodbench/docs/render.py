"""Renderers for the three intake channels and the text view an agent receives.

* PDF invoices are drawn with ReportLab and read back through a real text-layer
  extractor (pypdf), so hidden text (white, 1-point) reaches the agent exactly as it
  would from a production PDF parser, while a human looking at the page sees nothing.
* Structured e-invoices are UBL 2.1 documents following Peppol BIS Billing 3.0 with a
  PINT AE-style profile (CustomizationID ``urn:peppol:pint:billing-1@ae-1``, endpoint
  scheme 0235 with a 10-digit TIN). The agent view flattens them field by field,
  including the free-text fields where A3 places instructions.
* E-mails are rendered as RFC 5322 messages.
"""
from __future__ import annotations

import io
from datetime import timedelta
from email.message import EmailMessage
from functools import lru_cache
from xml.sax.saxutils import escape

from sodbench import ids
from sodbench.world.entities import Document, Email, InboxItem, World
from sodbench.world.generator import business_date

UBL_NS = {
    "inv": "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2",
    "cn": "urn:oasis:names:specification:ubl:schema:xsd:CreditNote-2",
    "cac": "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
    "cbc": "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
}


def _supplier_meta(world: World, doc: Document) -> dict:
    s = world.suppliers.get(doc.supplier_id_claimed) or world.pending_suppliers.get(doc.supplier_id_claimed) \
        or getattr(world, "fake_suppliers", {}).get(doc.supplier_id_claimed)
    if s is None:
        return {"address": "", "emirate": "", "email": "", "phone": ""}
    return {"address": s.address, "emirate": s.emirate, "email": s.contact.email, "phone": s.contact.phone}


# ----------------------------------------------------------------------------- PDF
def render_pdf(world: World, doc: Document) -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas

    meta = _supplier_meta(world, doc)
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4, invariant=1)
    W, H = A4
    y = H - 50
    c.setFont("Helvetica-Bold", 14)
    c.drawString(40, y, doc.supplier_name)
    c.setFont("Helvetica", 8)
    c.drawString(40, y - 12, f"{meta['address']}, {meta['emirate']}, United Arab Emirates")
    c.drawString(40, y - 22, f"TRN {doc.supplier_trn}   {meta['email']}   {meta['phone']}")
    c.setFont("Helvetica-Bold", 16)
    title = "TAX CREDIT NOTE" if doc.kind == "credit_note" else "TAX INVOICE"
    c.drawRightString(W - 40, y, title)
    y -= 50
    c.setFont("Helvetica", 9)
    issue = business_date(world.start, doc.issue_day)
    rows = [("Invoice number", doc.invoice_number), ("Issue date", issue.isoformat()),
            ("Due date", (issue + timedelta(days=30)).isoformat()),
            ("Purchase order", doc.po_ref or "n/a")]
    if doc.billing_reference:
        rows.append(("Reference", doc.billing_reference))
    for k, v in rows:
        c.drawString(40, y, f"{k}:")
        c.drawString(140, y, str(v))
        y -= 12
    c.drawString(330, y + 12 * len(rows), "Bill to:")
    c.drawString(330, y + 12 * (len(rows) - 1), world.org_name)
    c.drawString(330, y + 12 * (len(rows) - 2), f"TRN {world.org_trn}")
    y -= 14
    c.setFont("Helvetica-Bold", 9)
    for x, h in [(40, "Description"), (300, "Qty"), (350, "Unit"), (410, "Unit price"), (490, "Amount (AED)")]:
        c.drawString(x, y, h)
    y -= 12
    c.setFont("Helvetica", 9)
    for l in doc.lines:
        c.drawString(40, y, l.description[:48])
        c.drawRightString(330, y, f"{l.qty:g}")
        c.drawString(350, y, l.uom)
        c.drawRightString(470, y, f"{l.unit_price:,.2f}")
        c.drawRightString(555, y, f"{l.net:,.2f}")
        y -= 12
    y -= 8
    for k, v in [("Net amount", doc.net), (f"VAT {doc.vat_rate * 100:.0f}%", doc.vat), ("Total payable", doc.total)]:
        c.drawRightString(470, y, k)
        c.drawRightString(555, y, f"{v:,.2f}")
        y -= 12
    y -= 10
    c.setFont("Helvetica-Bold", 9)
    c.drawString(40, y, "Payment details")
    c.setFont("Helvetica", 9)
    c.drawString(40, y - 12, f"Bank: {ids.bank_name_for(doc.iban)}")
    c.drawString(40, y - 24, f"IBAN: {ids.format_iban(doc.iban)}")
    c.drawString(40, y - 36, f"Account name: {doc.supplier_name}")
    y -= 56
    for note in doc.notes:
        small = len(note) > 300
        c.setFont("Helvetica", 6 if small else 8)
        c.setFillColorRGB(0.35, 0.35, 0.35) if small else c.setFillColorRGB(0, 0, 0)
        for chunk in _wrap(note, 130 if small else 105):
            c.drawString(40, y, chunk)
            y -= 8 if small else 10
        y -= 4
    c.setFillColorRGB(0, 0, 0)
    for hidden in doc.hidden_text:   # A1: invisible on screen, present in the text layer
        c.setFillColorRGB(1, 1, 1)
        c.setFont("Helvetica", 1)
        hy = 30
        for chunk in _wrap(hidden, 200):
            c.drawString(40, hy, chunk)
            hy -= 1.2
        c.setFillColorRGB(0, 0, 0)
    c.showPage()
    c.save()
    return buf.getvalue()


def _wrap(text: str, width: int) -> list[str]:
    words, lines, cur = text.split(), [], ""
    for w in words:
        if len(cur) + len(w) + 1 > width:
            lines.append(cur)
            cur = w
        else:
            cur = (cur + " " + w).strip()
    if cur:
        lines.append(cur)
    return lines


def pdf_text(pdf_bytes: bytes) -> str:
    from pypdf import PdfReader
    reader = PdfReader(io.BytesIO(pdf_bytes))
    return "\n".join(page.extract_text() or "" for page in reader.pages)


# ----------------------------------------------------------------------------- UBL
def render_ubl(world: World, doc: Document) -> str:
    credit = doc.kind == "credit_note"
    root = "CreditNote" if credit else "Invoice"
    ns = UBL_NS["cn"] if credit else UBL_NS["inv"]
    issue = business_date(world.start, doc.issue_day)
    e = escape
    tin = doc.supplier_trn[:10]
    lines_xml = []
    for i, l in enumerate(doc.lines, 1):
        qty_tag = "CreditedQuantity" if credit else "InvoicedQuantity"
        line_tag = "CreditNoteLine" if credit else "InvoiceLine"
        desc = l.description + ((" " + doc.line_note) if (doc.line_note and i == 1) else "")
        lines_xml.append(
            f"<cac:{line_tag}><cbc:ID>{i}</cbc:ID><cbc:{qty_tag} unitCode=\"C62\">{l.qty:g}</cbc:{qty_tag}>"
            f"<cbc:LineExtensionAmount currencyID=\"AED\">{l.net:.2f}</cbc:LineExtensionAmount>"
            + (f"<cac:OrderLineReference><cbc:LineID>{l.line_no}</cbc:LineID></cac:OrderLineReference>" if l.line_no else "")
            + f"<cac:Item><cbc:Description>{e(desc)}</cbc:Description><cbc:Name>{e(l.description[:40])}</cbc:Name>"
            f"<cac:ClassifiedTaxCategory><cbc:ID>S</cbc:ID><cbc:Percent>{doc.vat_rate * 100:.0f}</cbc:Percent>"
            f"<cac:TaxScheme><cbc:ID>VAT</cbc:ID></cac:TaxScheme></cac:ClassifiedTaxCategory></cac:Item>"
            f"<cac:Price><cbc:PriceAmount currencyID=\"AED\">{l.unit_price:.2f}</cbc:PriceAmount></cac:Price>"
            f"</cac:{line_tag}>")
    notes = "".join(f"<cbc:Note>{e(n)}</cbc:Note>" for n in doc.notes)
    billing = (f"<cac:BillingReference><cac:InvoiceDocumentReference><cbc:ID>{e(doc.billing_reference)}</cbc:ID>"
               f"</cac:InvoiceDocumentReference></cac:BillingReference>") if doc.billing_reference else ""
    order = f"<cac:OrderReference><cbc:ID>{e(doc.po_ref)}</cbc:ID></cac:OrderReference>" if doc.po_ref else ""
    type_code = f"<cbc:CreditNoteTypeCode>381</cbc:CreditNoteTypeCode>" if credit else "<cbc:InvoiceTypeCode>380</cbc:InvoiceTypeCode>"
    instr = f"<cbc:InstructionNote>{e(doc.payment_note)}</cbc:InstructionNote>" if doc.payment_note else ""
    return (
        f"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<{root} xmlns=\"{ns}\" xmlns:cac=\"{UBL_NS['cac']}\" "
        f"xmlns:cbc=\"{UBL_NS['cbc']}\">"
        f"<cbc:CustomizationID>urn:peppol:pint:billing-1@ae-1</cbc:CustomizationID>"
        f"<cbc:ProfileID>urn:peppol:bis:billing</cbc:ProfileID>"
        f"<cbc:ID>{e(doc.invoice_number)}</cbc:ID><cbc:IssueDate>{issue.isoformat()}</cbc:IssueDate>"
        + ("" if credit else f"<cbc:DueDate>{(issue + timedelta(days=30)).isoformat()}</cbc:DueDate>")
        + f"{type_code}{notes}<cbc:DocumentCurrencyCode>AED</cbc:DocumentCurrencyCode>{order}{billing}"
        f"<cac:AccountingSupplierParty><cac:Party><cbc:EndpointID schemeID=\"0235\">{tin}</cbc:EndpointID>"
        f"<cac:PartyName><cbc:Name>{e(doc.supplier_name)}</cbc:Name></cac:PartyName>"
        f"<cac:PostalAddress><cac:Country><cbc:IdentificationCode>AE</cbc:IdentificationCode></cac:Country></cac:PostalAddress>"
        f"<cac:PartyTaxScheme><cbc:CompanyID>{doc.supplier_trn}</cbc:CompanyID><cac:TaxScheme><cbc:ID>VAT</cbc:ID>"
        f"</cac:TaxScheme></cac:PartyTaxScheme><cac:PartyLegalEntity><cbc:RegistrationName>{e(doc.supplier_name)}"
        f"</cbc:RegistrationName></cac:PartyLegalEntity></cac:Party></cac:AccountingSupplierParty>"
        f"<cac:AccountingCustomerParty><cac:Party><cbc:EndpointID schemeID=\"0235\">{world.org_trn[:10]}</cbc:EndpointID>"
        f"<cac:PartyLegalEntity><cbc:RegistrationName>{e(world.org_name)}</cbc:RegistrationName></cac:PartyLegalEntity>"
        f"</cac:Party></cac:AccountingCustomerParty>"
        f"<cac:PaymentMeans><cbc:PaymentMeansCode>30</cbc:PaymentMeansCode>{instr}"
        f"<cbc:PaymentID>{e(doc.invoice_number)}</cbc:PaymentID><cac:PayeeFinancialAccount><cbc:ID>{doc.iban}</cbc:ID>"
        f"<cbc:Name>{e(doc.supplier_name)}</cbc:Name></cac:PayeeFinancialAccount></cac:PaymentMeans>"
        f"<cac:TaxTotal><cbc:TaxAmount currencyID=\"AED\">{doc.vat:.2f}</cbc:TaxAmount></cac:TaxTotal>"
        f"<cac:LegalMonetaryTotal><cbc:LineExtensionAmount currencyID=\"AED\">{doc.net:.2f}</cbc:LineExtensionAmount>"
        f"<cbc:TaxExclusiveAmount currencyID=\"AED\">{doc.net:.2f}</cbc:TaxExclusiveAmount>"
        f"<cbc:TaxInclusiveAmount currencyID=\"AED\">{doc.total:.2f}</cbc:TaxInclusiveAmount>"
        f"<cbc:PayableAmount currencyID=\"AED\">{doc.total:.2f}</cbc:PayableAmount></cac:LegalMonetaryTotal>"
        + "".join(lines_xml) + f"</{root}>"
    )


def ubl_view(xml: str) -> str:
    """Flatten a UBL document into the field-by-field text an agent receives."""
    from lxml import etree
    root = etree.fromstring(xml.encode())
    q = lambda path: root.xpath(path, namespaces=UBL_NS)
    first = lambda path: (q(path) or [""])[0]
    credit = root.tag.endswith("CreditNote")
    out = [f"STRUCTURED E-{'CREDIT NOTE' if credit else 'INVOICE'} (UBL 2.1, profile {first('cbc:CustomizationID/text()')}) "
           f"received via Peppol",
           f"Document number: {first('cbc:ID/text()')} | Issue date: {first('cbc:IssueDate/text()')}",
           f"Supplier: {first('cac:AccountingSupplierParty/cac:Party/cac:PartyLegalEntity/cbc:RegistrationName/text()')}"
           f" | TRN {first('cac:AccountingSupplierParty/cac:Party/cac:PartyTaxScheme/cbc:CompanyID/text()')}"
           f" | Peppol endpoint 0235:{first('cac:AccountingSupplierParty/cac:Party/cbc:EndpointID/text()')}",
           f"Buyer: {first('cac:AccountingCustomerParty/cac:Party/cac:PartyLegalEntity/cbc:RegistrationName/text()')}"]
    po = first("cac:OrderReference/cbc:ID/text()")
    if po:
        out.append(f"Order reference: {po}")
    ref = first("cac:BillingReference/cac:InvoiceDocumentReference/cbc:ID/text()")
    if ref:
        out.append(f"Billing reference: {ref}")
    for n in q("cbc:Note/text()"):
        out.append(f"Note: {n}")
    tag = "cac:CreditNoteLine" if credit else "cac:InvoiceLine"
    qty = "cbc:CreditedQuantity" if credit else "cbc:InvoicedQuantity"
    for ln in q(tag):
        g = lambda p: (ln.xpath(p, namespaces=UBL_NS) or [""])[0]
        out.append(f"Line {g('cbc:ID/text()')} (PO line {g('cac:OrderLineReference/cbc:LineID/text()') or '-'}): "
                   f"{g('cac:Item/cbc:Description/text()')} | qty {g(qty + '/text()')} | unit price "
                   f"{g('cac:Price/cbc:PriceAmount/text()')} | net {g('cbc:LineExtensionAmount/text()')}")
    out.append(f"Payment means: credit transfer | Payee account (IBAN): "
               f"{first('cac:PaymentMeans/cac:PayeeFinancialAccount/cbc:ID/text()')}")
    instr = first("cac:PaymentMeans/cbc:InstructionNote/text()")
    if instr:
        out.append(f"Payment instruction note: {instr}")
    out.append(f"Totals: net {first('cac:LegalMonetaryTotal/cbc:TaxExclusiveAmount/text()')} | VAT "
               f"{first('cac:TaxTotal/cbc:TaxAmount/text()')} | payable {first('cac:LegalMonetaryTotal/cbc:PayableAmount/text()')} AED")
    return "\n".join(out)


# ----------------------------------------------------------------------------- e-mail
def render_eml(world: World, em: Email, attachments: list[tuple[str, bytes, str]] = ()) -> bytes:
    msg = EmailMessage()
    msg["From"] = f"{em.from_name} <{em.from_addr}>"
    msg["To"] = em.to_addr
    msg["Subject"] = em.subject
    msg["Date"] = business_date(world.start, em.day).strftime("%a, %d %b %Y 09:00:00 +0400")
    msg["Message-ID"] = f"<{em.msg_id}@sodbench.example>"
    msg.set_content(em.body)
    for name, data, mime in attachments:
        maintype, subtype = mime.split("/")
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)
    return bytes(msg)


# ----------------------------------------------------------------------------- agent view
_VIEW_CACHE: dict[tuple[int, str], str] = {}


def doc_view(world: World, doc: Document) -> str:
    fingerprint = hash((doc.iban, tuple(doc.notes), tuple(doc.hidden_text), doc.line_note, doc.payment_note,
                        doc.invoice_number, tuple((l.qty, l.unit_price) for l in doc.lines)))
    key = (id(world), f"{doc.doc_id}:{fingerprint}")
    if key in _VIEW_CACHE:
        return _VIEW_CACHE[key]
    if doc.channel == "ubl":
        text = ubl_view(render_ubl(world, doc))
    else:
        text = "PDF ATTACHMENT (text layer extracted)\n" + pdf_text(render_pdf(world, doc))
    _VIEW_CACHE[key] = text
    return text


def item_view(world: World, item: InboxItem) -> str:
    """The exact untrusted text an agent receives for one inbox item."""
    parts = []
    if item.email is not None:
        em = item.email
        parts.append(f"From: {em.from_name} <{em.from_addr}>\nTo: {em.to_addr}\n"
                     f"Date: {business_date(world.start, em.day).isoformat()}\nSubject: {em.subject}\n\n{em.body}")
    if item.doc is not None:
        parts.append(doc_view(world, item.doc))
    return "\n\n".join(parts)
