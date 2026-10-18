"""combine_finder.py - Tier 3: propose cherry-pick COMBINATIONS from md code nodes. Output = HYPOTHESIS cards only.

A symbol that is weak on a dimension (no error handling, undocumented, long, high branching) is paired with a symbol of the same language that is strong on that dimension
and plausibly interface-compatible (same language, overlapping calls, similar size). The score is a ranking of ideas, NOT a prediction that the merged code works. A hypothesis
becomes a CANDIDATE only after a contained run passes its tests, and LOCKED only when a replay reproduces the result hash (Conductor rule). Every card carries the strictest
license class of the two parents and the taint flag; use_gate decides what a build may do with it.

Safety and scale: node files are untrusted (they derive from third-party code). A repo name must be one plain path component and every file must stay inside the node root; a file
over MAX_NODE_BYTES or one that does not parse is SKIPPED AND COUNTED (the report says how many), never a crash and never silently dropped. Pairing uses an index on shared call names,
so cost grows with the pairs that can actually score, not with the square of all symbols, and only the best `top` cards are kept in memory."""
import heapq
import json
import os
import re

from vega_dkg import safe_paths as sp
from vega_harness import use_gate as ug

COMPLEMENT = {"no error handling": "handles errors", "undocumented": "documented", "long": "small", "high branching": "low branching"}
MAX_NODE_BYTES = 5 * 1024 * 1024
MAX_POOL = 200_000
_SYM = re.compile(r"^## (function|class) `([^`\n]+)` L(\d+)-(\d+)  \((vn1_\w+)\)\n- scores: (.*)\n- weaknesses: (.*)\n- strengths: (.*)\n", re.M)


def parse_node(path):
    """One md code node -> dict, or None if it is not a well-formed node."""
    t = sp.read_capped(path, MAX_NODE_BYTES).decode("utf-8", errors="replace")
    parts = t.split("---")
    if len(parts) < 3:
        return None
    fm = dict(re.findall(r"^(\w+): (.*)$", parts[1], re.M))
    syms = []
    for m in _SYM.finditer(t):
        kind, name, a, b, vid, sc, wk, st = m.groups()
        fi = re.search(r"fan_in_by_name=(\d+)", sc)
        calls = re.search(r"- calls: (.*)", t[m.end():m.end() + 4000].split("\n## ")[0])
        syms.append({"vega_id": vid, "name": name, "kind": kind, "lines": max(1, int(b) - int(a) + 1), "weak": wk, "strong": st,
                     "calls": set(calls.group(1).split(", ")) if calls else set(), "fan_in": int(fi.group(1)) if fi else 0,
                     "tested": "tested_by_name=True" in sc})
    try:
        return {"path": json.loads(fm.get("path", '""')), "repo": json.loads(fm.get("repo", '""')), "language": json.loads(fm.get("language", '""')),
                "license_class": json.loads(fm.get("license_class", '"UNKNOWN"')), "syms": syms}
    except ValueError:
        return None


def load(repos, root):
    """Returns (nodes, report). report counts what was skipped and why."""
    nodes, report = [], {"files": 0, "skipped_too_big": 0, "skipped_malformed": 0, "skipped_unsafe": 0}
    for r in repos:
        sp.safe_name(r)
        base = sp.contained(root, r)
        for dp, _, fs in os.walk(base):
            for f in fs:
                if not f.endswith(".md"):
                    continue
                report["files"] += 1
                try:
                    n = parse_node(sp.contained(base, os.path.relpath(os.path.join(dp, f), base)))
                except sp.PathRefused as exc:
                    report["skipped_too_big" if "over the" in str(exc) else "skipped_unsafe"] += 1
                    continue
                except OSError:
                    report["skipped_unsafe"] += 1
                    continue
                if n is None:
                    report["skipped_malformed"] += 1
                else:
                    nodes.append(n)
    return nodes, report


def weak_dims(s):
    return [d for d in COMPLEMENT if d in s["weak"]]


def propose(nodes, top=20, min_overlap=0.1, dims=None):
    """dims: only these weakness dimensions (goal-conditioning); None = all. Returns the best `top` hypothesis cards, best first."""
    if isinstance(top, bool) or not isinstance(top, int) or top < 0:
        raise ValueError("top is a whole number, 0 or more")
    pool = [(n, s) for n in nodes for s in n["syms"] if s["kind"] == "function"]
    if len(pool) > MAX_POOL:
        raise ValueError(f"{len(pool)} functions is over the {MAX_POOL} limit: run per repo or per language")
    by_call = {}
    for i, (_, s) in enumerate(pool):
        for c in s["calls"]:
            by_call.setdefault(c, []).append(i)
    heap, tick = [], 0
    for ia, (na, a) in enumerate(pool):
        wd = [d for d in weak_dims(a) if not dims or d in dims]
        if not wd or not a["calls"] or min_overlap <= 0:
            continue
        partners = set()
        for c in a["calls"]:
            partners.update(by_call.get(c, ()))
        for ib in partners:
            nb, b = pool[ib]
            if ib == ia or nb["language"] != na["language"] or b["name"] == a["name"]:
                continue                      # same name = a duplicate, not a complement
            union = a["calls"] | b["calls"]
            overlap = len(a["calls"] & b["calls"]) / len(union) if union else 0.0
            if overlap < min_overlap:
                continue
            size_fit = 1.0 - abs(a["lines"] - b["lines"]) / max(a["lines"], b["lines"], 1)
            reuse = (1 if b["tested"] else 0) + min(b["fan_in"], 3) / 3.0
            base = 0.45 * overlap + 0.25 * size_fit + 0.30 * reuse / 2.0 + (0.1 if nb["repo"] != na["repo"] else 0.0)   # cross-repo pairs rank higher
            strict = min([ug.klass_of(na["license_class"]), ug.klass_of(nb["license_class"])], key=ug.STRICT.index)
            for dim in wd:
                if COMPLEMENT[dim] not in b["strong"]:
                    continue
                score = round(base, 4)
                card = {"status": "hypothesis", "fixes": dim,
                        "weak_symbol": {"repo": na["repo"], "path": na["path"], "name": a["name"], "vega_id": a["vega_id"]},
                        "strong_symbol": {"repo": nb["repo"], "path": nb["path"], "name": b["name"], "vega_id": b["vega_id"]},
                        "language": na["language"], "call_overlap": round(overlap, 3), "size_fit": round(size_fit, 3), "score": score,
                        "strictest_license_class": strict, "tainted_if_used": True,
                        "public_build": "clean-room only", "personal_build": "contained use; output TAINTED",
                        "needs": ["contained run in the evaluation sandbox", "tests that pass", "replay that reproduces the result hash"],
                        "note": "a ranking of ideas, not a prediction that the merge works"}
                tick += 1
                item = (score, -tick, card)               # -tick: earlier proposals win ties, deterministically
                if len(heap) < top:
                    heapq.heappush(heap, item)
                elif top and item > heap[0]:
                    heapq.heapreplace(heap, item)
    return [c for _, _, c in sorted(heap, reverse=True)]


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True, help="folder holding <repo>/**/*.md code nodes")
    ap.add_argument("--top", type=int, default=20)
    ap.add_argument("repos", nargs="+")
    a = ap.parse_args(argv)
    nodes, report = load(a.repos, a.root)
    props = propose(nodes, top=a.top)
    out = os.path.join(a.root, "_hypotheses")
    os.makedirs(out, exist_ok=True)
    name = "hypotheses_%s.jsonl" % re.sub(r"[^A-Za-z0-9_.-]", "_", "_".join(a.repos))[:120]
    sp.atomic_write(os.path.join(out, name), "".join(json.dumps(c) + "\n" for c in props))
    print("nodes", len(nodes), "symbols", sum(len(n["syms"]) for n in nodes), "hypotheses", len(props), "report", report)
    for c in props[:5]:
        print("%.3f fix '%s': %s::%s  <-  %s::%s (overlap %.2f)" % (c["score"], c["fixes"], c["weak_symbol"]["repo"], c["weak_symbol"]["name"],
                                                                 c["strong_symbol"]["repo"], c["strong_symbol"]["name"], c["call_overlap"]))


if __name__ == "__main__":
    main()
