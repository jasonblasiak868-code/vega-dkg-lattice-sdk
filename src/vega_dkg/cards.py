"""cards.py - DNA cards for a library of repos, one plane, read-only over the library.

For each repo it writes <out>/cards/<repo>.jsonl holding:
  repo   node  : license class, use boundary, policy, score dimensions (wilson lower bound), audit status, archive hash, group
  code   nodes : one card per graph node (vega_id from the crosswalk; kind; label; path; location; degree; edge confidence; license class + use boundary inherited; dna_hash)
  doc    nodes : one card per KEPT file in INGEST_MANIFEST.csv (sha256, path, linked code node count); skipped files are recorded as 'skipped' and never read
and <out>/coverage.json (per repo: files KEPT, files that have at least one node, nodes, gaps).
Fields the layers do not have are 'not_scored' (unbacked is not false). Full text is never truncated.

Safety (the library is untrusted input): the repo name must be one plain path component; every file read is size-capped and must resolve inside the repo folder; a card file or
coverage.json is written atomically (a crash leaves the old one); a repo that fails is recorded with its full error text and the run continues.

  build(repo, lib_root, out_root, crosswalk, matrix, groups) ; python -m vega_dkg.cards --lib LIB --out OUT --matrix M.json --crosswalk CW.db [--groups G.md] REPO..."""
import csv
import hashlib
import io
import json
import os
import re

from vega_dkg import safe_paths as sp
from vega_dkg import vega_id as vid

NS = "not_scored"
MAX_JSON = 512 * 1024 * 1024
MAX_MANIFEST = 200 * 1024 * 1024


def h(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


def load_groups(path):
    g = {}
    if not path:
        return g
    try:
        cur = None
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("#"):
                    cur = line.lstrip("# ").strip()
                elif cur:
                    for m in re.findall(r"[A-Za-z0-9_.\-]+", line):
                        g.setdefault(m, cur)
    except OSError:
        pass  # reviewed: a missing groups file means every repo's group is not_scored, which is the stated default
    return g


def _json_in(root, *parts):
    p = os.path.join(root, *parts)
    if not os.path.exists(p):
        return {}
    return json.loads(sp.read_capped(sp.contained(root, *parts), MAX_JSON).decode("utf-8"))


def build(repo, lib_root, out_root, crosswalk, matrix, groups):
    """crosswalk: an open vega_dkg.vega_id.Crosswalk. Returns the coverage row for this repo."""
    sp.safe_name(repo)
    rd = sp.contained(lib_root, repo)
    row = matrix.get(repo, {})
    ver = _json_in(rd, "verify.json")
    sc = _json_in(rd, "score.json")
    dims = {k: (v.get("wilson_lower") if isinstance(v, dict) else None) for k, v in (sc.get("dimensions") or {}).items()}
    def known(v):                                                        # a field the matrix does not have is not_scored, never an empty value that reads like "no"
        return NS if v is None else v
    inherit = {"license_class": row.get("license_class", "UNKNOWN"), "personal_build": known(row.get("personal_build")),
               "public_build": known(row.get("public_build")), "taint_if_used": row.get("taint_if_used", True)}
    repo_id = vid.vega_id("library", repo, "repo", repo, "", 0)
    g = _json_in(rd, "graphify-out", "graph.json") or {"nodes": [], "links": []}
    nodes = [n for n in g.get("nodes", []) if isinstance(n, dict) and "id" in n]
    links = [e for e in g.get("links", g.get("edges", [])) if isinstance(e, dict)]
    report = crosswalk.add_many("library", [dict(local_id=repo + "::" + str(n["id"]), universe=repo, path=n.get("source_file"), kind=n.get("file_type"),
                                                 label=n.get("label"), location=n.get("source_location")) for n in nodes])
    deg, conf = {}, {}
    cmap = {"EXTRACTED": 1.0, "INFERRED": 0.5, "AMBIGUOUS": 0.25}
    for e in links:
        for end in (e.get("source"), e.get("target")):
            deg[end] = deg.get(end, 0) + 1
            conf.setdefault(end, []).append(cmap.get(str(e.get("confidence")), 0.5))
    file_nodes, missing_id, cards = {}, 0, []
    for n in nodes:
        lid = repo + "::" + str(n["id"])
        v = crosswalk.con.execute("select vega_id, collision_group from crosswalk where layer='library' and local_id=?", (lid,)).fetchone()
        if not v:
            missing_id += 1
        card = {"kind": "code_node", "vega_id": v[0] if v else NS, "collision_group": v[1] if v else NS, "repo": repo, "repo_vega_id": repo_id,
                "local_id": n["id"], "node_kind": n.get("node_kind"), "file_type": n.get("file_type"), "label": n.get("label"),
                "path": n.get("source_file"), "location": n.get("source_location"), "degree": deg.get(n["id"], 0),
                "mean_edge_confidence": round(sum(conf[n["id"]]) / len(conf[n["id"]]), 3) if n["id"] in conf else NS,
                "inherited": inherit, "repo_scores": dims, "kinetic_energy": NS, "scorer_outputs": NS}
        card["dna_hash"] = h(card)
        cards.append(card)
        p = (n.get("source_file") or "").replace("\\", "/").lower()
        file_nodes[p] = file_nodes.get(p, 0) + 1
    docs, kept, skipped, covered = [], 0, [], 0
    mp = os.path.join(rd, "INGEST_MANIFEST.csv")
    if os.path.exists(mp):
        raw = sp.read_capped(sp.contained(rd, "INGEST_MANIFEST.csv"), MAX_MANIFEST).decode("utf-8", "replace")
        rows_in = list(csv.DictReader(io.StringIO(raw, newline="")))
        kept_paths = [(r.get("detail") or "").replace("\\", "/").lower() for r in rows_in if r.get("disposition", "") == "KEPT"]
        # An archive's top folder (for example basal-main/) is in the manifest paths but not in the graph paths. Strip it only when EVERY kept path shares one top folder and no graph path starts with
        # that folder; otherwise a file such as src/a.py would borrow the nodes of a different top-level a.py.
        tops = {p.split("/", 1)[0] for p in kept_paths}
        strip = None
        if kept_paths and len(tops) == 1 and all("/" in p for p in kept_paths):
            top = next(iter(tops))
            if not any(fp.startswith(top + "/") for fp in file_nodes):
                strip = top
        for r in rows_in:
            disp = r.get("disposition", "")
            detail = (r.get("detail") or "").replace("\\", "/")
            if disp == "KEPT":
                kept += 1
                low = detail.lower()
                nn = file_nodes.get(low, 0) or (file_nodes.get(low[len(strip) + 1:], 0) if strip and low.startswith(strip + "/") else 0)
                covered += 1 if nn else 0
                d = {"kind": "doc_node", "vega_id": vid.vega_id(repo, detail, "doc", os.path.basename(detail), "", 0), "repo": repo, "repo_vega_id": repo_id,
                     "path": detail, "sha256": r.get("sha256"), "code_nodes_in_file": nn, "inherited": inherit}
                d["dna_hash"] = h(d)
                docs.append(d)
            else:
                skipped.append({"path": r.get("source_path"), "disposition": disp})
    repo_card = {"kind": "repo_node", "vega_id": repo_id, "repo": repo, "group": groups.get(repo, NS), **inherit,
                 "audit_policy": known(row.get("audit_policy")), "audit_status": row.get("audit_status") or ver.get("status") or NS,
                 "archive_sha256": known(ver.get("archive_sha256")), "score_dimensions": dims or NS, "files_kept": kept,
                 "files_skipped": len(skipped), "code_nodes": len(cards), "doc_nodes": len(docs), "graph_tag": repo}
    repo_card["dna_hash"] = h(repo_card)
    text = "".join(json.dumps(c, ensure_ascii=False) + "\n" for c in [repo_card] + docs + cards)
    sp.atomic_write(sp.contained(os.path.join(out_root, "cards"), repo + ".jsonl"), text)
    gaps = [d["path"] for d in docs if d["code_nodes_in_file"] == 0]
    return {"repo": repo, "license_class": inherit["license_class"], "files_kept": kept, "files_with_nodes": covered,
            "coverage_by_file": round(covered / kept, 3) if kept else NS, "code_nodes": len(cards), "nodes_without_vega_id": missing_id,
            "id_conflicts": report["conflicts"], "skipped": len(skipped), "files_without_nodes": gaps, "graph_tag": repo}


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--lib", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--matrix", required=True)
    ap.add_argument("--crosswalk", required=True)
    ap.add_argument("--groups")
    ap.add_argument("repos", nargs="*")
    a = ap.parse_args(argv)
    with open(a.matrix, encoding="utf-8") as fh:
        matrix = {r["repo"]: r for r in json.load(fh) if isinstance(r, dict) and "repo" in r}
    repos = a.repos or sorted(matrix)
    groups = load_groups(a.groups)
    cp = os.path.join(a.out, "coverage.json")
    cov = json.load(open(cp, encoding="utf-8")) if os.path.exists(cp) else {}
    with vid.Crosswalk(a.crosswalk) as cw:
        for r in repos:
            try:
                s = build(r, a.lib, a.out, cw, matrix, groups)
                cov[r] = s
                print("%-45s %-18s kept %-5s withnodes %-5s nodes %-6s noid %s" % (r, s["license_class"], s["files_kept"], s["files_with_nodes"], s["code_nodes"], s["nodes_without_vega_id"]), flush=True)
            except Exception as e:  # reviewed: one repo failing is recorded in full and the run continues
                cov[r] = {"repo": r, "error": type(e).__name__ + ": " + str(e)}
                print(r, "ERROR", cov[r]["error"], flush=True)
            sp.atomic_write(cp, json.dumps(cov, indent=1))


if __name__ == "__main__":
    main()
