"""Search arXiv (API) for recent papers on given topics; print compact candidate lists."""
import sys, time, urllib.parse, urllib.request, xml.etree.ElementTree as ET
NS = {"a": "http://www.w3.org/2005/Atom"}
def search(q, n=6, start="202501010000", end="202611072359"):
    query = f"({q}) AND submittedDate:[{start} TO {end}]"
    url = "https://export.arxiv.org/api/query?" + urllib.parse.urlencode(
        {"search_query": query, "max_results": n, "sortBy": "relevance"})
    for attempt in range(4):
        try:
            root = ET.fromstring(urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "sodbench-refcheck/0.1"}), timeout=60).read())
            break
        except Exception as e:
            time.sleep(6 * (attempt + 1))
    else:
        return []
    out = []
    for e in root.findall("a:entry", NS):
        i = e.findtext("a:id", namespaces=NS).split("/abs/")[-1].split("v")[0]
        t = " ".join(e.findtext("a:title", namespaces=NS).split())
        au = [a.findtext("a:name", namespaces=NS) for a in e.findall("a:author", NS)]
        out.append((i, e.findtext("a:published", namespaces=NS)[:7], au[0].split()[-1] if au else "?", t))
    return out
if __name__ == "__main__":
    for line in open(sys.argv[1]):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        tag, q = line.split("|", 1)
        print("==", tag)
        for i, d, a, t in search(q):
            print(f"  {i:11s} {d} {a[:14]:14s} {t[:105]}")
        time.sleep(3.2)
