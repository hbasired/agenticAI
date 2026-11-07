"""Verify arXiv references in bulk via the public arXiv API.

Usage:
    python scripts/verify_arxiv.py references/arxiv_ids.txt references/arxiv_meta.json

The input file has one arXiv identifier per line (optionally followed by
whitespace and a free-text label). Lines starting with '#' are ignored.
The output JSON maps each identifier to its title, authors, dates,
primary category, journal reference, DOI and a short abstract, or to an
error marker when the identifier does not resolve. The script respects
arXiv's request-rate guidance (one request every three seconds).
"""
from __future__ import annotations

import json
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET

API = "https://export.arxiv.org/api/query?id_list={ids}&max_results={n}"
NS = {"a": "http://www.w3.org/2005/Atom", "arxiv": "http://arxiv.org/schemas/atom"}


def read_ids(path: str) -> list[tuple[str, str]]:
    out = []
    with open(path, encoding="utf8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(maxsplit=1)
            out.append((parts[0], parts[1] if len(parts) > 1 else ""))
    return out


def fetch(batch: list[str]) -> dict[str, dict]:
    url = API.format(ids=",".join(batch), n=len(batch))
    req = urllib.request.Request(url, headers={"User-Agent": "sodbench-refcheck/0.1"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        root = ET.fromstring(resp.read())
    found: dict[str, dict] = {}
    for entry in root.findall("a:entry", NS):
        eid = entry.findtext("a:id", default="", namespaces=NS)
        if "/abs/" not in eid:
            continue
        short = eid.split("/abs/")[1]
        base = short.split("v")[0] if "v" in short else short
        title = " ".join((entry.findtext("a:title", default="", namespaces=NS) or "").split())
        if title.lower() == "error":
            continue
        found[base] = {
            "title": title,
            "authors": [a.findtext("a:name", default="", namespaces=NS) for a in entry.findall("a:author", NS)],
            "published": entry.findtext("a:published", default="", namespaces=NS)[:10],
            "updated": entry.findtext("a:updated", default="", namespaces=NS)[:10],
            "primary_category": (entry.find("arxiv:primary_category", NS).attrib.get("term")
                                 if entry.find("arxiv:primary_category", NS) is not None else ""),
            "journal_ref": entry.findtext("arxiv:journal_ref", default="", namespaces=NS),
            "doi": entry.findtext("arxiv:doi", default="", namespaces=NS),
            "comment": " ".join((entry.findtext("arxiv:comment", default="", namespaces=NS) or "").split()),
            "abstract": " ".join((entry.findtext("a:summary", default="", namespaces=NS) or "").split())[:900],
        }
    return found


def main() -> None:
    src, dst = sys.argv[1], sys.argv[2]
    ids = read_ids(src)
    try:
        with open(dst, encoding="utf8") as fh:
            meta = json.load(fh)
    except FileNotFoundError:
        meta = {}
    todo = [i for i, _ in ids if i not in meta or "error" in meta[i]]
    for k in range(0, len(todo), 25):
        batch = todo[k:k + 25]
        for attempt in range(4):
            try:
                got = fetch(batch)
                break
            except Exception as exc:  # network hiccup: back off and retry
                print("retry", attempt, exc, file=sys.stderr)
                time.sleep(5 * (attempt + 1))
        else:
            got = {}
        for i in batch:
            meta[i] = got.get(i, {"error": "not found"})
        time.sleep(3.1)
    labels = dict(ids)
    for i, _ in ids:
        m = meta.get(i, {})
        if "error" in m:
            print(f"{i:12s} NOT FOUND   [{labels[i]}]")
        else:
            au = m["authors"]
            who = (au[0].split()[-1] + (" et al." if len(au) > 1 else "")) if au else "?"
            print(f"{i:12s} {m['published'][:7]} {who:22s} {m['title'][:95]}")
    with open(dst, "w", encoding="utf8") as fh:
        json.dump(meta, fh, indent=1, ensure_ascii=False)


if __name__ == "__main__":
    main()
