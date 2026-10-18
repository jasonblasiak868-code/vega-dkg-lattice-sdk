"""knowledge_import.py - grow the DKG from open public knowledge sources, offline, in governed parts. This is code in the DKG's own SDK, not something the model does.

SOURCES (each carries its licence; none is guessed):
  wikidata   the structured facts behind Wikipedia: items, labels, descriptions and item-to-item statements.   CC0-1.0      clean (no taint, no attribution needed)
  openalex   scholarly works: ids, titles, years, authors, citations (abstract text is NOT taken: publishers hold rights).   CC0-1.0 metadata
  arxiv      the arXiv metadata snapshot: ids, titles, authors, categories (abstract kept only as a hash and a length).      CC0-1.0 metadata
WIKIPEDIA text is deliberately NOT imported here: it is share-alike (CC-BY-SA) and would be tainted; it would need its own adapter and the use gate. WIKILEAKS is not a source: leaked documents have
provenance and legal problems that make them unsuitable for a knowledge base you may disclose or build a company on.

HOW IT WORKS: read a dump file you already downloaded (plain, .gz or .bz2; Wikidata's array-of-lines format is understood), one line at a time, never loading the file whole. Each line becomes NODES and EDGES in the
DKG's card shape (vega_id, dna_hash, inherited licence and taint) and is written to PARTS that never pass the size limit (default 90 MB, under the 100 MB rule), each part hashed, with a MANIFEST listing the parts
and one BATCH HASH over them. Facts are marked EXTRACTED (said by the source), never INFERRED, and a statement's published references are counted: a statement with no reference is kept and labelled unreferenced
(unbacked is not false). Nothing is truncated: a line too large to read safely is counted and reported, not cut.
THE COMMITMENT: a bulk import cannot ask a human to sign every node, so the human signs ONE commitment for the whole batch: batch_commit_params() gives the exact action and parameters (source, batch hash, record
counts); load() refuses to run without a commit_check that approves exactly those parameters, loads through the loader you supply, and counts back what was stored against what was meant.
HONEST LIMITS: a source can be wrong (Wikidata is edited by the public): these records are claims by that source, with their references, not truth. This module reads files; it makes no network call. It does not
decide what is relevant: you give it a filter. Entity formats change over time; unknown shapes are counted as skipped, never guessed."""
import bz2
import gzip
import hashlib
import io
import json
import os

from vega_dkg import cards as dkgcards
from vega_dkg import vega_id as vid

MAX_LINE = 8 * 1024 * 1024
MAX_PART = 90 * 1024 * 1024
HARD_PART = 100 * 1024 * 1024
MAX_RECORD = 2 * 1024 * 1024

SOURCES = {
    "wikidata": {"license": "CC0-1.0", "license_class": "PERMISSIVE", "taint": False, "attribution_required": False},
    "openalex": {"license": "CC0-1.0", "license_class": "PERMISSIVE", "taint": False, "attribution_required": False},
    "arxiv": {"license": "CC0-1.0", "license_class": "PERMISSIVE", "taint": False, "attribution_required": False},
}


class ImportRefused(ValueError):
    pass


# ---- reading --------------------------------------------------------------------------------------------------------------
def open_dump(path):
    p = os.fspath(path)
    if p.endswith(".gz"):
        return gzip.open(p, "rb")
    if p.endswith(".bz2"):
        return bz2.open(p, "rb")
    return open(p, "rb")


def sha256_file(path, chunk=1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def iter_json_lines(path, stats, max_line=MAX_LINE):
    """Yield one decoded object per line. Understands a JSON array written one element per line (trailing commas, '[' and ']' lines). Bad lines and over-long lines are counted in `stats`."""
    with open_dump(path) as fh:
        reader = io.BufferedReader(fh) if not hasattr(fh, "peek") else fh
        while True:
            raw = reader.readline(max_line + 1)
            if not raw:
                return
            if len(raw) > max_line and not raw.endswith(b"\n"):
                stats["too_long"] = stats.get("too_long", 0) + 1
                while True:                                           # skip the rest of that line without keeping it
                    rest = reader.readline(1 << 20)
                    if not rest or rest.endswith(b"\n"):
                        break
                continue
            s = raw.strip()
            if s.startswith(b"\xef\xbb\xbf"):
                s = s[3:]
            if s in (b"", b"[", b"]"):
                continue
            if s.endswith(b","):
                s = s[:-1]
            try:
                yield json.loads(s.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                stats["bad_json"] = stats.get("bad_json", 0) + 1


# ---- records -----------------------------------------------------------------------------------------------------------------
def _inherit(source):
    s = SOURCES[source]
    return {"license_class": s["license_class"], "taint_if_used": s["taint"], "license": s["license"], "source": source}


def _node(source, kind, source_id, label, extra=None):
    body = {"kind": kind, "vega_id": vid.vega_id(source, source_id, kind, source_id, "", 0), "source": source, "source_id": source_id, "label": label, "extracted": True,
            "inherited": _inherit(source)}
    if extra:
        body.update(extra)
    body["dna_hash"] = dkgcards.h(body)
    return body


def _edge(source, relation, src_kind, src_id, dst_kind, dst_id, extra=None):
    body = {"kind": "edge", "relation": relation, "source": source, "src": vid.vega_id(source, src_id, src_kind, src_id, "", 0), "dst": vid.vega_id(source, dst_id, dst_kind, dst_id, "", 0),
            "extracted": True, "inherited": _inherit(source)}
    if extra:
        body.update(extra)
    body["dna_hash"] = dkgcards.h(body)
    return body


class Filter:
    """Which items to take. qids: only these; instance_of: only items that are an instance of one of these; languages: label languages kept; max_nodes: stop after this many items."""

    def __init__(self, qids=None, instance_of=None, languages=("en",), max_nodes=None):
        self.qids = frozenset(qids) if qids is not None else None
        self.instance_of = frozenset(instance_of) if instance_of is not None else None
        self.languages = tuple(languages)
        self.max_nodes = max_nodes
        if not self.languages or any(not isinstance(l, str) or not l for l in self.languages):
            raise ImportRefused("languages is a non-empty list of language codes")
        if max_nodes is not None and (isinstance(max_nodes, bool) or not isinstance(max_nodes, int) or max_nodes < 1):
            raise ImportRefused("max_nodes is a positive whole number")


def _wd_targets(claims, prop=None):
    out = []
    for p, stmts in (claims or {}).items():
        if prop is not None and p != prop:
            continue
        for st in stmts or []:
            try:
                if st.get("rank") == "deprecated":
                    continue
                snak = st["mainsnak"]
                if snak.get("snaktype") != "value":
                    continue
                dv = snak["datavalue"]
                if dv.get("type") != "wikibase-entityid":
                    continue
                refs = st.get("references") or []
                out.append((p, dv["value"]["id"], len(refs), st.get("rank", "normal")))
            except (KeyError, TypeError, AttributeError):
                continue
    return out


def wikidata_records(entity: dict, flt: Filter, stats: dict):
    """-> (nodes, edges, referenced_target_ids) for one dump line, or ([], [], []) if the filter or the shape says skip."""
    try:
        qid = entity["id"]
        if entity.get("type") != "item" or not isinstance(qid, str) or not qid.startswith("Q") or not qid[1:].isdigit():
            stats["skipped_shape"] = stats.get("skipped_shape", 0) + 1
            return [], [], []
    except (KeyError, TypeError, AttributeError):
        stats["skipped_shape"] = stats.get("skipped_shape", 0) + 1
        return [], [], []
    if flt.qids is not None and qid not in flt.qids:
        return [], [], []
    claims = entity.get("claims") or {}
    targets = _wd_targets(claims)
    if flt.instance_of is not None and not any(p == "P31" and t in flt.instance_of for p, t, _, _ in targets):
        return [], [], []
    labels, descs = {}, {}
    for lang in flt.languages:
        v = (entity.get("labels") or {}).get(lang)
        if isinstance(v, dict) and isinstance(v.get("value"), str):
            labels[lang] = v["value"]
        d = (entity.get("descriptions") or {}).get(lang)
        if isinstance(d, dict) and isinstance(d.get("value"), str):
            descs[lang] = d["value"]
    label = labels.get(flt.languages[0]) or next(iter(labels.values()), dkgcards.NS)
    node = _node("wikidata", "wd_item", qid, label, {"labels": labels, "descriptions": descs, "instance_of": sorted({t for p, t, _, _ in targets if p == "P31"}), "statement_count": sum(len(v or []) for v in claims.values())})
    edges = [_edge("wikidata", p, "wd_item", qid, "wd_item", t, {"references": n, "referenced": n > 0, "rank": rank}) for p, t, n, rank in targets]
    return [node], edges, sorted({t for _, t, _, _ in targets})


def _oa_id(url):
    return str(url).rsplit("/", 1)[-1] if url else None


def openalex_records(work: dict, flt: Filter, stats: dict):
    try:
        wid = _oa_id(work["id"])
        if not wid or not wid.startswith("W"):
            raise KeyError
    except (KeyError, TypeError, AttributeError):
        stats["skipped_shape"] = stats.get("skipped_shape", 0) + 1
        return [], [], []
    title = work.get("title") or work.get("display_name") or dkgcards.NS
    node = _node("openalex", "paper", wid, title, {"year": work.get("publication_year"), "doi": work.get("doi"), "work_type": work.get("type"), "abstract_present": bool(work.get("abstract_inverted_index"))})
    edges, refs = [], []
    for ref in work.get("referenced_works") or []:
        rid = _oa_id(ref)
        if rid:
            edges.append(_edge("openalex", "CITES", "paper", wid, "paper", rid))
            refs.append(rid)
    for a in work.get("authorships") or []:
        try:
            aid = _oa_id(a["author"]["id"])
            if aid:
                edges.append(_edge("openalex", "AUTHORED_BY", "paper", wid, "author", aid, {"author_name": a["author"].get("display_name")}))
        except (KeyError, TypeError):
            continue
    return [node], edges, refs


def arxiv_records(rec: dict, flt: Filter, stats: dict):
    try:
        aid = rec["id"]
        if not isinstance(aid, str) or not aid:
            raise KeyError
    except (KeyError, TypeError):
        stats["skipped_shape"] = stats.get("skipped_shape", 0) + 1
        return [], [], []
    abstract = rec.get("abstract") if isinstance(rec.get("abstract"), str) else ""
    node = _node("arxiv", "paper", aid, rec.get("title") or dkgcards.NS, {"categories": str(rec.get("categories") or "").split(), "authors": rec.get("authors"),
                                                                           "updated": rec.get("update_date"), "abstract_sha256": hashlib.sha256(abstract.encode("utf-8")).hexdigest() if abstract else None, "abstract_chars": len(abstract)})
    return [node], [], []


ADAPTERS = {"wikidata": wikidata_records, "openalex": openalex_records, "arxiv": arxiv_records}


# ---- writing parts -----------------------------------------------------------------------------------------------------------
class PartWriter:
    def __init__(self, out_dir, source, max_bytes=MAX_PART):
        if source not in SOURCES:
            raise ImportRefused("unknown source")
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or not 1024 <= max_bytes <= HARD_PART:
            raise ImportRefused("max_bytes is 1024 up to the %d byte limit" % HARD_PART)
        self.dir, self.source, self.max = os.fspath(out_dir), source, max_bytes
        os.makedirs(self.dir, exist_ok=True)
        self.parts, self._fh, self._h, self._bytes, self._records = [], None, None, 0, 0

    def _open(self):
        name = "%s-%06d.jsonl" % (self.source, len(self.parts) + 1)
        self._cur = name
        self._fh = open(os.path.join(self.dir, name), "wb")
        self._h, self._bytes, self._records = hashlib.sha256(), 0, 0

    def _close(self):
        if self._fh is not None:
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self._fh.close()
            self.parts.append({"file": self._cur, "sha256": self._h.hexdigest(), "bytes": self._bytes, "records": self._records})
            self._fh = None

    def write(self, rec: dict) -> bool:
        line = (json.dumps(rec, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        if len(line) > MAX_RECORD:
            return False
        if self._fh is not None and self._bytes + len(line) > self.max:
            self._close()
        if self._fh is None:
            self._open()
        self._fh.write(line)
        self._h.update(line)
        self._bytes += len(line)
        self._records += 1
        return True

    def finish(self):
        self._close()
        return self.parts


def batch_sha256(parts) -> str:
    h = hashlib.sha256(b"VEGA-DKG-IMPORT-1")
    for p in parts:
        h.update(("|%s|%s|%d|%d" % (p["file"], p["sha256"], p["bytes"], p["records"])).encode("utf-8"))
    return h.hexdigest()


def import_dump(path, source, out_dir, flt: Filter = None, max_part_bytes=MAX_PART, stubs=True, max_ids=20_000_000) -> dict:
    """Read the dump, write parts and a manifest into out_dir. -> the manifest."""
    if source not in SOURCES:
        raise ImportRefused("unknown source %r" % (source,))
    flt = flt or Filter()
    adapter = ADAPTERS[source]
    stats = {}
    writer = PartWriter(out_dir, source, max_part_bytes)
    seen, wanted_targets, n_nodes, n_edges, dup = set(), set(), 0, 0, 0
    dump_sha = sha256_file(path)
    for obj in iter_json_lines(path, stats):
        if flt.max_nodes is not None and n_nodes >= flt.max_nodes:
            stats["stopped_at_max_nodes"] = True
            break
        nodes, edges, targets = adapter(obj, flt, stats)
        for n in nodes:
            if n["vega_id"] in seen:
                dup += 1
                continue
            if len(seen) >= max_ids:
                raise ImportRefused("more than %d distinct ids: raise max_ids deliberately or filter harder" % max_ids)
            if writer.write(n):
                seen.add(n["vega_id"])
                n_nodes += 1
            else:
                stats["record_too_large"] = stats.get("record_too_large", 0) + 1
        for e in edges:
            if writer.write(e):
                n_edges += 1
            else:
                stats["record_too_large"] = stats.get("record_too_large", 0) + 1
        wanted_targets.update(targets)
    n_stubs = 0
    if stubs:                                                         # an edge must not point at nothing: targets outside the filter get a bare stub node, clearly not extracted from an item
        for tid in sorted(wanted_targets):
            kind = {"wikidata": "wd_item", "openalex": "paper"}.get(source)
            if kind is None:
                continue
            node = _node(source, kind, tid, dkgcards.NS, {"stub": True})
            if node["vega_id"] not in seen and writer.write(node):
                seen.add(node["vega_id"])
                n_stubs += 1
    parts = writer.finish()
    manifest = {"version": 1, "source": source, "license": SOURCES[source]["license"], "license_class": SOURCES[source]["license_class"], "tainted": SOURCES[source]["taint"],
                "dump_file": os.path.basename(os.fspath(path)), "dump_sha256": dump_sha, "parts": parts, "counts": {"nodes": n_nodes, "edges": n_edges, "stubs": n_stubs, "duplicates": dup},
                "skipped": stats, "batch_sha256": batch_sha256(parts)}
    with open(os.path.join(os.fspath(out_dir), "%s-MANIFEST.json" % source), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=1, sort_keys=True)
    return manifest


# ---- verifying and loading ------------------------------------------------------------------------------------------------------------
def verify_parts(manifest: dict, out_dir) -> list:
    """Re-hash every part against the manifest. -> a list of problems (empty means every part is exactly what was written)."""
    problems = []
    try:
        if manifest["batch_sha256"] != batch_sha256(manifest["parts"]):
            problems.append("the batch hash does not match the part list")
        for p in manifest["parts"]:
            f = os.path.join(os.fspath(out_dir), os.path.basename(p["file"]))
            if os.path.basename(p["file"]) != p["file"]:
                problems.append("part name %r is not a plain file name" % p["file"])
                continue
            if not os.path.exists(f):
                problems.append("%s is missing" % p["file"])
            elif sha256_file(f) != p["sha256"] or os.path.getsize(f) != p["bytes"]:
                problems.append("%s changed since it was written" % p["file"])
            elif os.path.getsize(f) > HARD_PART:
                problems.append("%s is over the size limit" % p["file"])
    except (KeyError, TypeError) as exc:
        problems.append("the manifest is malformed: %s" % exc)
    return problems


def batch_commit_params(manifest: dict) -> dict:
    """What the human signs: one commitment for this exact batch."""
    return {"action": "dkg_import", "params": {"source": manifest["source"], "batch_sha256": manifest["batch_sha256"], "nodes": manifest["counts"]["nodes"], "edges": manifest["counts"]["edges"]}}


def load(manifest: dict, out_dir, loader, commit_check, batch_size: int = 1000) -> dict:
    """Load verified parts through `loader(list_of_records) -> int stored`, only with an approving commit_check(action, params), and count back. Raises ImportRefused on any failure; nothing is loaded before the checks pass."""
    bad = verify_parts(manifest, out_dir)
    if bad:
        raise ImportRefused("the parts do not match the manifest: " + "; ".join(bad))
    req = batch_commit_params(manifest)
    try:
        approved = commit_check(req["action"], req["params"]) is True
    except Exception:                                                  # noqa: BLE001 - a crashing check is a refusal
        approved = False
    if not approved:
        raise ImportRefused("no human commitment for exactly this batch: nothing was loaded")
    sent = stored = 0
    batch = []
    for p in manifest["parts"]:
        with open(os.path.join(os.fspath(out_dir), p["file"]), "rb") as fh:
            for line in fh:
                batch.append(json.loads(line.decode("utf-8")))
                if len(batch) >= batch_size:
                    sent += len(batch)
                    stored += _store(loader, batch)
                    batch = []
    if batch:
        sent += len(batch)
        stored += _store(loader, batch)
    expect = manifest["counts"]["nodes"] + manifest["counts"]["edges"] + manifest["counts"]["stubs"]
    if sent != expect or stored != sent:
        raise ImportRefused("count-back failed: manifest %d, sent %d, stored %d" % (expect, sent, stored))
    return {"sent": sent, "stored": stored, "batch_sha256": manifest["batch_sha256"]}


def _store(loader, batch):
    n = loader(batch)
    if isinstance(n, bool) or not isinstance(n, int) or n < 0:
        raise ImportRefused("the loader must return how many records it stored")
    return n
