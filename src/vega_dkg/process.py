"""process.py - "process this repo": ONE workflow from the archive to the finished record, with a receipt for every stage. Either every stage passed and the report says COMPLETE, or the first failure
stops it and the report says exactly which stage failed and which passed. There is no half-done state reported as done.

Stages, in order:
  intake     archive hash, size and member-name safety (no traversal, no absolute paths, no zip bomb)
  extract    unpacked into its own new folder; nothing from it is ever executed
  vet        static review: license files and declared licenses (strictest wins), credential-shaped values, outbound hosts, risky calls, installer scripts, secret-named files
  library    copied into the repo library, ingest manifest, verification record, repo card, a row in the use matrix (existing rows are never changed)
  md_nodes   one markdown code node per source file; one row per VARIABLE in variables.jsonl (writes, reads, role, owning symbol's strengths and weaknesses)
  graph      the code graph, built without any model call
  cards      repo, doc and code cards with vega ids in the crosswalk
  scores     score.json: provenance, documentation, tests, graph connectedness, extracted-edge share, internal-edge share (Wilson lower bounds) and symbol-level aggregates
  dag        every receipt above, hash-chained in the process DAG
  dkg_load   the graph loaded into the DKG database under the repo's own tag, then COUNTED back: the stored node count must equal the graph's
  report     PROCESS_REPORT.md in the library folder: what the repo is, how it may be used, what was and was not measured

HONEST LIMITS written into every report: the vet is a static read, not proof of safety; scores measure structure, not whether code works; variable roles are read from syntax trees (writes and reads inside one symbol),
not data-flow analysis across files; languages without a parser are listed as not extracted.

  python -m vega_dkg.process ARCHIVE.zip --config config.json [--name NAME] [--class CLASS]      or     process(archive, cfg)"""
import csv
import hashlib
import json
import os
import pathlib
import re
import shutil
import sys
import time
import zipfile

from vega_custody import proc, safepaths as sp
from vega_custody.dag.dag import Dag, contains_credential
from vega_dkg import cards, md_nodes, vega_id

STAGES = ("intake", "extract", "vet", "library", "md_nodes", "graph", "cards", "scores", "dag", "dkg_load", "report")
STRICT = ["NON_COMMERCIAL_OR_RESTRICTED", "STRONG_COPYLEFT", "WEAK_COPYLEFT", "NO_LICENSE_FILE", "PERMISSIVE"]       # strictest first
MAX_ARCHIVE_BYTES = 4 * 1024 ** 3
MAX_UNPACKED_BYTES = 8 * 1024 ** 3
MAX_RATIO = 200
MAX_MEMBERS = 200_000
TEXT_EXT = {".py", ".js", ".jsx", ".mjs", ".ts", ".tsx", ".java", ".go", ".cs", ".c", ".h", ".cpp", ".rs", ".rb", ".php", ".kt", ".sh", ".ps1", ".md", ".txt", ".json", ".toml", ".yaml", ".yml", ".cfg", ".ini", ".html", ".css", ".vue", ".ipynb"}
CODE_EXT = {".py", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts", ".ts", ".tsx", ".java", ".go", ".cs", ".c", ".h", ".cpp", ".rs", ".rb", ".php", ".kt", ".sh", ".vue"}
TEST_RX = re.compile(r"(^|[\\/_.-])(test|tests|spec|__tests__)([\\/_.-]|$)", re.I)
LICENSE_RULES = [(re.compile(r"GNU AFFERO GENERAL PUBLIC LICENSE", re.I), "STRONG_COPYLEFT", "AGPL"), (re.compile(r"GNU GENERAL PUBLIC LICENSE", re.I), "STRONG_COPYLEFT", "GPL"),
                 (re.compile(r"GNU LESSER GENERAL PUBLIC LICENSE|GNU LIBRARY GENERAL PUBLIC", re.I), "WEAK_COPYLEFT", "LGPL"), (re.compile(r"Mozilla Public License|Eclipse Public License|Common Development and Distribution", re.I), "WEAK_COPYLEFT", "MPL/EPL/CDDL"),
                 (re.compile(r"Apache License", re.I), "PERMISSIVE", "Apache-2.0"), (re.compile(r"Permission is hereby granted, free of charge", re.I), "PERMISSIVE", "MIT"),
                 (re.compile(r"Redistribution and use in source and binary forms", re.I), "PERMISSIVE", "BSD"), (re.compile(r"This is free and unencumbered software", re.I), "PERMISSIVE", "Unlicense"),
                 (re.compile(r"non-?commercial|research use only|no commercial use", re.I), "NON_COMMERCIAL_OR_RESTRICTED", "non-commercial wording")]
SPDX_RX = re.compile(r"(?:license\s*[=:]\s*|\"license\"\s*:\s*)[\"']?\(?([A-Za-z0-9.+\- ]{2,40}?)[\"')]?\s*(?:[,}\n]|$)", re.I)
LICENSE_FILES = re.compile(r"^(licen[sc]e|copying|copyright|notice|unlicense)([.\-_].*)?$", re.I)
RISKY_RX = re.compile(r"\beval\(|\bexec\(|pickle\.loads?\(|os\.system\(|shell\s*=\s*True|base64\.b64decode\(|\bnew Function\(|child_process|subprocess\.")
INSTALLER_RX = re.compile(r"curl[^\n|]*\|\s*(ba)?sh|wget[^\n|]*\|\s*(ba)?sh|\biex\b|Invoke-Expression|Invoke-WebRequest[^\n]*\|")
HOST_RX = re.compile(r"https?://([A-Za-z0-9._-]+)")
PLACEHOLDER_HOSTS = ("example.", "localhost", "127.0.0.1", ".".join(["0"] * 4), ".test", "invalid", "w3.org", "schema.org")  # reviewed: a list of placeholder hosts to IGNORE when counting outbound hosts; nothing binds or connects


class ProcessRefused(ValueError):
    pass


class _MatrixLock:
    """A lock file beside the use matrix, so two runs adding rows cannot overwrite each other's row."""

    def __init__(self, path, timeout=60.0):
        self.path, self.timeout, self.fd = path + ".lock", timeout, None

    def __enter__(self):
        end = time.time() + self.timeout
        while True:
            try:
                self.fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                return self
            except FileExistsError:
                try:
                    if time.time() - os.path.getmtime(self.path) > 300:          # a lock left by a crashed run
                        os.remove(self.path)
                        continue
                except OSError:
                    pass
                if time.time() > end:
                    raise ProcessRefused("the use matrix is locked by another run")
                time.sleep(0.05)

    def __exit__(self, *a):
        os.close(self.fd)
        try:
            os.remove(self.path)
        except OSError:
            pass


def add_matrix_row(cfg, row):
    """Add one row to the use matrix. The file is re-read under a lock, so rows added by other runs since this run started are kept, and a repo that already has a row is refused. Returns the rows."""
    with _MatrixLock(cfg.matrix_path):
        with open(cfg.matrix_path, encoding="utf-8") as fh:
            rows = json.load(fh)
        if not isinstance(rows, list):
            raise ProcessRefused("the use matrix is a list of repo rows")
        if any(isinstance(r, dict) and r.get("repo") == row["repo"] for r in rows):
            raise ProcessRefused(f"{row['repo']} already has a row in the use matrix")
        bak = cfg.matrix_path + ".bak_" + time.strftime("%Y%m%d")
        if not os.path.exists(bak):
            shutil.copyfile(cfg.matrix_path, bak)
        rows.append(row)
        sp.atomic_write(cfg.matrix_path, json.dumps(rows, indent=1))
        return rows


def _secret_named(name):
    low = name.lower()
    return low.startswith(".env") and not low.endswith((".example", ".sample", ".template"))


class Config:
    def __init__(self, vetting_dir, library, md_out, one_plane, matrix_path, dag_dir, neo4j_db="codegraphs", graphify="graphify", loader=None, load_dkg=True, timeout=3600):
        self.vetting_dir, self.library, self.md_out, self.one_plane = map(str, (vetting_dir, library, md_out, one_plane))
        self.matrix_path, self.dag_dir, self.neo4j_db, self.graphify, self.loader, self.load_dkg, self.timeout = str(matrix_path), str(dag_dir), neo4j_db, graphify, loader, load_dkg, timeout

    @classmethod
    def from_file(cls, path):
        with open(path, encoding="utf-8") as fh:
            return cls(**json.load(fh))


def strictest(classes):
    classes = [c for c in classes if c in STRICT]
    return min(classes, key=STRICT.index) if classes else "NO_LICENSE_FILE"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ----------------------------------------------------------------------------------------------------------------------------- stages
def stage_intake(archive, name):
    if not os.path.isfile(archive):
        raise ProcessRefused(f"{archive} is not a file")
    size = os.path.getsize(archive)
    if size > MAX_ARCHIVE_BYTES:
        raise ProcessRefused(f"archive is {size} bytes, over {MAX_ARCHIVE_BYTES}")
    try:
        zf = zipfile.ZipFile(archive)
    except zipfile.BadZipFile as exc:
        raise ProcessRefused("not a readable zip archive") from exc
    infos = zf.infolist()
    if len(infos) > MAX_MEMBERS:
        raise ProcessRefused(f"{len(infos)} members is over {MAX_MEMBERS}")
    bad = [i.filename for i in infos if i.filename.startswith(("/", "\\")) or ".." in re.split(r"[\\/]", i.filename) or ":" in i.filename or "\x00" in i.filename]
    if bad:
        raise ProcessRefused(f"unsafe member names, e.g. {bad[:3]!r}")
    total = sum(i.file_size for i in infos)
    if total > MAX_UNPACKED_BYTES or (size and total / size > MAX_RATIO and total > 50 * 1024 * 1024):
        raise ProcessRefused(f"unpacked size {total} bytes against a {size} byte archive looks like a zip bomb")
    sp.safe_name(name)
    return {"name": name, "archive_sha256": sha256_file(archive), "archive_bytes": size, "members": len(infos), "unpacked_bytes": total}


def stage_extract(archive, cfg, name):
    dest = os.path.join(cfg.vetting_dir, name)
    if os.path.exists(dest) and os.listdir(dest):
        raise ProcessRefused(f"{dest} already holds files: refusing to extract over them (a repo is processed once per name)")
    os.makedirs(dest, exist_ok=True)
    zf = zipfile.ZipFile(archive)
    unextractable = []
    for info in zf.infolist():                                                         # one member at a time: a file name this operating system refuses must not block the whole repo
        try:
            zf.extract(info, dest)
        except (OSError, ValueError, zipfile.BadZipFile) as exc:
            unextractable.append({"member": info.filename.encode("unicode_escape").decode("ascii"), "why": type(exc).__name__})
    tops = [d for d in os.listdir(dest) if os.path.isdir(os.path.join(dest, d))]
    root = os.path.join(dest, tops[0]) if len(tops) == 1 and len([f for f in os.listdir(dest)]) == 1 else dest
    return {"extracted_to": dest, "source_root": root, "unextractable_members": unextractable}


def stage_vet(root):
    lic_found, risky_prod, risky_test, installers, secrets, secret_named, hosts = [], {}, {}, [], [], [], {}
    declared = []
    for dp, dn, fs in os.walk(root):
        dn[:] = [d for d in dn if d not in ("node_modules", ".git")]
        for f in fs:
            p = os.path.join(dp, f)
            rel = os.path.relpath(p, root).replace("\\", "/")
            low = f.lower()
            if low.startswith(".env") and not low.endswith((".example", ".sample", ".template")):
                secret_named.append(rel)
                continue
            ext = os.path.splitext(low)[1]
            is_test = bool(TEST_RX.search(rel))
            if (LICENSE_FILES.match(os.path.splitext(f)[0]) or LICENSE_FILES.match(f)) and ext in ("", ".md", ".txt", ".rst"):          # a source file called license_utils.py is not a licence
                try:
                    text = sp.read_capped(p, 1 << 20).decode("utf-8", "replace")
                except (OSError, sp.PathRefused):
                    continue
                hits = [(c, label) for rx, c, label in LICENSE_RULES if rx.search(text[:20000])]
                lic_found.append({"file": rel, "matches": [h[1] for h in hits], "class": strictest([h[0] for h in hits]) if hits else "NO_LICENSE_FILE", "root": "/" not in rel})
            if ext not in TEXT_EXT:
                continue
            try:
                text = sp.read_capped(p, 2 * 1024 * 1024).decode("utf-8", "replace")
            except (OSError, sp.PathRefused):
                continue
            if f in ("pyproject.toml", "package.json", "setup.py", "setup.cfg"):
                declared += [m.strip() for m in SPDX_RX.findall(text)][:3]
            if contains_credential(text):
                secrets.append(rel)
            if ext in CODE_EXT or ext in (".sh", ".ps1"):
                n = len(RISKY_RX.findall(text))
                if n:
                    (risky_test if is_test else risky_prod)[rel] = n
                if INSTALLER_RX.search(text):
                    installers.append(rel)
            for h in HOST_RX.findall(text[:400_000]):
                if not any(x in h.lower() for x in PLACEHOLDER_HOSTS):
                    hosts[h.lower()] = hosts.get(h.lower(), 0) + 1
    # Only a licence file at the root licenses the repo. A licence inside a subfolder (vendored code) covers the code it sits with: it can make the class STRICTER, never more permissive.
    root_classes = [x["class"] for x in lic_found if x["matches"] and x["root"]]
    sub_classes = [x["class"] for x in lic_found if x["matches"] and not x["root"] and x["class"] != "PERMISSIVE"]
    cls = strictest(root_classes + sub_classes) if (root_classes or sub_classes) else "NO_LICENSE_FILE"
    flags = []
    if not root_classes and any(x["matches"] and not x["root"] for x in lic_found):
        flags.append("license file(s) found only in subfolders: they license the code they sit with, not this repo, which states no license of its own")
    if secrets:
        flags.append(f"{len(secrets)} file(s) hold credential-shaped values (often test fixtures: read before trusting)")
    if installers:
        flags.append(f"installer script(s) pipe a download into a shell: {installers[:3]}")
    if secret_named:
        flags.append("secret-named file(s) were skipped, never read")
    if len({x["class"] for x in lic_found if x["matches"]}) > 1:
        flags.append("more than one license class present: the strictest applies to the whole repo")
    top_hosts = sorted(hosts.items(), key=lambda kv: -kv[1])[:15]
    return {"license_class": cls, "license_files": lic_found, "declared_licenses": sorted(set(declared)), "credential_shaped_files": secrets[:50], "credential_shaped_file_count": len(secrets),
            "secret_named_skipped": secret_named, "risky_call_files": len(risky_prod), "risky_call_total_in_production_code": sum(risky_prod.values()), "risky_call_total_in_tests": sum(risky_test.values()),
            "top_risky_files": sorted(risky_prod.items(), key=lambda kv: -kv[1])[:10], "installer_scripts": installers, "outbound_hosts": top_hosts, "flags": flags,
            "verdict": "REVIEW_FLAGS" if flags else "NO_RED_FLAGS_STATIC", "basis": "static read only: nothing executed; not proof of safety"}


def stage_library(archive, cfg, name, root, vet, intake, matrix_rows, cls):
    dst = os.path.join(cfg.library, name)
    if os.path.exists(dst):
        raise ProcessRefused(f"{dst} already exists in the library: leaving it alone")
    if any(r.get("repo") == name for r in matrix_rows):
        raise ProcessRefused(f"{name} already has a row in the use matrix")
    base_ignore = shutil.ignore_patterns("node_modules", ".git")

    def ignore(src_dir, names):                                                          # a secret-named file or folder is listed in the ledger but never copied into the library
        return set(base_ignore(src_dir, names)) | {n for n in names if _secret_named(n)}
    shutil.copytree(root, os.path.join(dst, name), ignore=ignore)
    rows, kept, code, tests, docs = [], 0, 0, 0, 0
    for dp, _, fs in os.walk(os.path.join(dst, name)):
        for f in fs:
            p = os.path.join(dp, f)
            rel = os.path.relpath(p, dst).replace("\\", "/")
            rows.append((p, sha256_file(p), "KEPT", rel))
            kept += 1
            ext = os.path.splitext(f)[1].lower()
            code += ext in CODE_EXT
            tests += ext in CODE_EXT and bool(TEST_RX.search(rel))
            docs += ext in (".md", ".rst", ".txt")
    for dp, dn, fs in os.walk(root):
        dn[:] = [d for d in dn if d not in ("node_modules", ".git")]
        for n in list(dn) + fs:
            if _secret_named(n):
                rows.append((os.path.join(dst, name, os.path.relpath(os.path.join(dp, n), root)), "", "SKIPPED_SECRET", "name matches secret pattern"))
        dn[:] = [d for d in dn if not _secret_named(d)]
    with open(os.path.join(dst, "INGEST_MANIFEST.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["source_path", "sha256", "disposition", "detail"])
        w.writerows(rows)
    verify = {"name": name, "source": os.path.basename(archive), "archive_sha256": intake["archive_sha256"], "members": intake["members"], "ledger": {"KEPT": kept, "SKIPPED_SECRET": len(rows) - kept},
              "ledger_total": len(rows), "status": "COMPLETE", "license": f"{cls} ({', '.join(vet['declared_licenses']) or 'no declared license'})", "vet_verdict": vet["verdict"]}
    with open(os.path.join(dst, "verify.json"), "w", encoding="utf-8") as fh:
        json.dump(verify, fh, indent=1)
    row = {"repo": name, "license_class": cls, "audit_policy": "processed by vega_dkg.process; static vet only; contained use", "personal_build": "contained use; output TAINTED",
           "public_build": "clean-room only", "sdk_pack": "card+scores+license+pointer", "taint_if_used": True, "files": kept, "audit_status": "COMPLETE"}
    return {"library_path": dst, "kept": kept, "ledger_total": len(rows), "code_files": code, "test_files": tests, "doc_files": docs, "matrix_row": row}


def stage_graph(cfg, name, timeout):
    src = os.path.join(cfg.library, name, name)
    r = proc.run_bounded([cfg.graphify, "update", src, "--no-cluster"], timeout=timeout, cap=1 << 20)
    if r["status"] != "ok" or r["returncode"] != 0:
        raise ProcessRefused(f"graph build failed ({r['status']}, exit {r['returncode']}): {(r['err'] or r['out'])[-300:].decode('utf-8', 'replace')}")
    g = os.path.join(src, "graphify-out", "graph.json")
    if not os.path.isfile(g):
        raise ProcessRefused("graph build reported success but wrote no graph.json")
    os.makedirs(os.path.join(cfg.library, name, "graphify-out"), exist_ok=True)
    shutil.copyfile(g, os.path.join(cfg.library, name, "graphify-out", "graph.json"))
    with open(g, encoding="utf-8") as fh:
        gj = json.load(fh)
    return {"graph_nodes": len(gj.get("nodes", [])), "graph_edges": len(gj.get("links", gj.get("edges", []))), "graph_sha256": sha256_file(g)}


def wilson(pos, n, z=1.96):
    if n == 0:
        return None
    p = pos / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    m = z * (p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5
    return round((c - m) / d, 4)


def stage_scores(cfg, name, lib, md, graph_path):
    with open(graph_path, encoding="utf-8") as fh:
        g = json.load(fh)
    nodes, links = g.get("nodes", []), g.get("links", g.get("edges", []))
    ids = {n["id"] for n in nodes if "id" in n}
    touched = set()
    internal = extracted = 0
    for e in links:
        touched.add(e.get("source"))
        touched.add(e.get("target"))
        internal += e.get("source") in ids and e.get("target") in ids
        extracted += str(e.get("confidence")) == "EXTRACTED"
    vrows = []
    if md.get("variables_path") and os.path.getsize(md["variables_path"]):
        with open(md["variables_path"], encoding="utf-8") as vf:
            vrows = [json.loads(line) for line in vf]
    syms = {}
    for v in vrows:
        syms.setdefault(v["symbol_vega_id"], v)
    dims = {"provenance_completeness": {"wilson_lower": wilson(lib["kept"], lib.get("ledger_total", lib["kept"])), "pos": lib["kept"], "n": lib.get("ledger_total", lib["kept"])},
            "documentation_share": {"wilson_lower": wilson(lib["doc_files"], lib["kept"]), "pos": lib["doc_files"], "n": lib["kept"]},
            "test_share_of_code": {"wilson_lower": wilson(lib["test_files"], lib["code_files"]), "pos": lib["test_files"], "n": lib["code_files"]},
            "graph_connectedness": {"wilson_lower": wilson(len(ids & touched), len(ids)), "pos": len(ids & touched), "n": len(ids)},
            "graph_edges_extracted_not_inferred": {"wilson_lower": wilson(extracted, len(links)), "pos": extracted, "n": len(links)},
            "graph_edges_internal": {"wilson_lower": wilson(internal, len(links)), "pos": internal, "n": len(links)}}
    roles = {"write_only": 0, "read_only": 0, "read_write": 0}
    for v in vrows:
        roles[v["role"]] += 1
    agg = {"symbols_with_variables": len(syms), "variables": len(vrows), "variable_roles": roles,
           "write_only_share_wilson_lower": wilson(roles["write_only"], len(vrows))}
    out = {"name": name, "dimensions": dims, "symbol_aggregates": agg, "md_files": md["files"], "md_symbols": md["symbols"], "files_not_extracted": md["not_extracted"], "files_failed_to_parse": md["failed"]}
    d = os.path.join(cfg.library, name)
    with open(os.path.join(d, "score.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1)
    with open(os.path.join(d, "score_card.md"), "w", encoding="utf-8") as fh:
        fh.write(f"# score card: {name}\n\n" + "\n".join(f"- {k}: Wilson lower bound {v['wilson_lower']} ({v['pos']}/{v['n']})" for k, v in dims.items()) +
                 f"\n\n- variables scored: {agg['variables']} (write-only {roles['write_only']}, read-only {roles['read_only']}, read-write {roles['read_write']})\n- files not extracted (no parser): {md['not_extracted']}; failed to parse: {md['failed']}\n"
                 "\nScores measure structure. They do not show that the code works.\n")
    return {"dimensions": {k: v["wilson_lower"] for k, v in dims.items()}, **agg}


def stage_dkg_load(cfg, name, graph_nodes):
    if not cfg.load_dkg:
        raise ProcessRefused("DKG load is disabled in this configuration: the workflow is NOT complete")
    if not cfg.loader:
        raise ProcessRefused("no loader configured")
    g = os.path.join(cfg.library, name, "graphify-out", "graph.json")
    r = proc.run_bounded([sys.executable, cfg.loader, g, cfg.neo4j_db, "--tag", name, "--prefix"], timeout=cfg.timeout, cap=1 << 20)
    text = r["out"].decode("utf-8", "replace")
    m = re.search(r"GNode\[%s\]=([\d,]+)" % re.escape(name), text)
    if r["returncode"] != 0 or not m:
        raise ProcessRefused(f"DKG load failed (exit {r['returncode']}): {(r['err'] or r['out'])[-300:].decode('utf-8', 'replace')}")
    stored = int(m.group(1).replace(",", ""))
    if stored != graph_nodes:
        raise ProcessRefused(f"DKG holds {stored} nodes for {name}, the graph has {graph_nodes}: not complete")
    return {"database": cfg.neo4j_db, "graph_tag": name, "nodes_stored": stored, "nodes_in_graph": graph_nodes, "count_matches": True}


REPORT_TXT = """# PROCESS REPORT: {name}

status: **{status}**   processed: {when}

## What this is
license class: **{cls}** ({lic}); vet verdict: **{verdict}**. {flags}

## How it may be used
{use}

## Measured
- files kept {kept} (code {code}, tests {tests}); markdown code nodes {md_files}, symbols {md_symbols}, variables scored {variables}
- graph: {graph_nodes} nodes, {graph_edges} edges, stored in the DKG ({db}, tag {name}): {dkg}
- score dimensions (Wilson lower bounds): {dims}

## Receipts
{receipts}

## Honest limits
The vet is a static read, not proof of safety. Scores measure structure, not whether the code works. Variable roles come from syntax trees inside one symbol, not data flow across files.
Languages without a parser are listed as not extracted (here: {not_extracted} file(s), {failed} failed to parse).
"""


def use_text(cls):
    return {"PERMISSIVE": "Contained use for any build. Cherry-picking needs attribution and the notice files. A public release still follows the library rule: clean-room only unless the owner decides otherwise.",
            "WEAK_COPYLEFT": "Reference or contained use. Linking or copying can carry copyleft duties for the combined work: counsel decides. Public builds: clean-room only.",
            "STRONG_COPYLEFT": "Method reference and contained use only. Nothing from it goes into a public build (network copyleft too). Reimplement the idea clean-room from a specification.",
            "NON_COMMERCIAL_OR_RESTRICTED": "Read in quarantine only. Terms limit use.",
            "NO_LICENSE_FILE": "No license means no permission: read in quarantine only; clean-room for anything public."}[cls]


# ----------------------------------------------------------------------------------------------------------------------------- driver
def process(archive, cfg, name=None, license_class=None):
    """Run every stage. Returns {"complete": bool, "name", "stages": {stage: receipt or failure}, "failed_at": stage or None}."""
    if license_class is not None and license_class not in STRICT:
        raise ProcessRefused(f"license class {license_class!r} is not one of {STRICT}")
    archive = os.path.abspath(archive)
    name = name if name is not None else re.sub(r"\.zip$", "", os.path.basename(archive), flags=re.I)
    receipts, failed = {}, None
    os.makedirs(cfg.dag_dir, exist_ok=True)
    dag = Dag([pathlib.Path(cfg.dag_dir) / "PROCESS_DAG.jsonl"], [pathlib.Path(cfg.dag_dir) / "PROCESS_DAG_LOC.jsonl"])
    with open(cfg.matrix_path, encoding="utf-8") as fh:
        matrix_rows = json.load(fh)
    state = {}

    def run(stage, fn):
        nonlocal failed
        if failed:
            receipts[stage] = {"ok": False, "skipped": f"not run: {failed} failed"}
            return
        t0 = time.time()
        try:
            res = fn()
            receipts[stage] = {"ok": True, "seconds": round(time.time() - t0, 1), **{k: v for k, v in res.items() if k not in ("matrix_row", "source_root")}}
            state[stage] = res
        except Exception as exc:  # reviewed: every failure is a receipt that stops the workflow and is reported by stage; nothing is retried or hidden
            failed = stage
            receipts[stage] = {"ok": False, "error": f"{type(exc).__name__}: {exc}", "seconds": round(time.time() - t0, 1)}

    run("intake", lambda: stage_intake(archive, name))
    run("extract", lambda: stage_extract(archive, cfg, name))
    run("vet", lambda: stage_vet(state["extract"]["source_root"]))
    cls = license_class or (state.get("vet") or {}).get("license_class", "NO_LICENSE_FILE")
    def do_library():
        lib = stage_library(archive, cfg, name, state["extract"]["source_root"], state["vet"], state["intake"], matrix_rows, cls)
        rows = add_matrix_row(cfg, lib["matrix_row"])                                  # only after the library copy fully succeeded, and re-read under a lock so no other run's row is lost
        matrix_rows[:] = rows
        return lib
    run("library", do_library)
    matrix = {r["repo"]: r for r in matrix_rows}
    vpath = os.path.join(cfg.library, name, "variables.jsonl")
    run("md_nodes", lambda: {**md_nodes.build_repo(name, cfg.library, cfg.md_out, matrix, variables_path=vpath), "variables_path": vpath})
    run("graph", lambda: stage_graph(cfg, name, cfg.timeout))

    def do_cards():
        with vega_id.Crosswalk(os.path.join(cfg.one_plane, "crosswalk.db")) as cw:
            c = cards.build(name, cfg.library, cfg.one_plane, cw, matrix, cards.load_groups(None))
        if c["nodes_without_vega_id"] or c["id_conflicts"]:
            raise ProcessRefused(f"{c['nodes_without_vega_id']} nodes without a vega id, {len(c['id_conflicts'])} id conflicts")
        return {k: c[k] for k in ("files_kept", "files_with_nodes", "code_nodes", "coverage_by_file")}
    run("cards", do_cards)
    run("scores", lambda: stage_scores(cfg, name, state["library"], state["md_nodes"], os.path.join(cfg.library, name, "graphify-out", "graph.json")))
    run("dkg_load", lambda: stage_dkg_load(cfg, name, state["graph"]["graph_nodes"]))
    # dag + report come last so they can hold every receipt (a failed run still records what happened)
    entry = None
    try:
        entry = dag.record("PROCESS_REPO", {"repo": name, "archive_sha256": (receipts.get("intake") or {}).get("archive_sha256"), "failed_at": failed,
                                            "stages": {k: bool(v.get("ok")) for k, v in receipts.items()}, "license_class": cls})
        receipts["dag"] = {"ok": True, "entry_hash": entry["entry_hash"]}
    except Exception as exc:  # reviewed: a record that cannot be written is itself a failed stage
        failed = failed or "dag"
        receipts["dag"] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    complete = not failed and all(receipts.get(s, {}).get("ok") for s in STAGES if s != "report")
    out_dir = os.path.join(cfg.library, name)
    if os.path.isdir(out_dir):
        v, s_, lib, md, gr = (state.get(k) or {} for k in ("vet", "scores", "library", "md_nodes", "graph"))
        text = REPORT_TXT.format(name=name, status="COMPLETE" if complete else f"INCOMPLETE: failed at {failed}", when=time.strftime("%Y-%m-%d %H:%M"), cls=cls, lic=", ".join(v.get("declared_licenses", [])) or "none declared",
                                 verdict=v.get("verdict", "not run"), flags=" ".join(v.get("flags", [])), use=use_text(cls if cls in STRICT else "NO_LICENSE_FILE"), kept=lib.get("kept"), code=lib.get("code_files"),
                                 tests=lib.get("test_files"), md_files=md.get("files"), md_symbols=md.get("symbols"), variables=md.get("variables"), graph_nodes=gr.get("graph_nodes"), graph_edges=gr.get("graph_edges"),
                                 db=cfg.neo4j_db, dkg=(receipts.get("dkg_load") or {}).get("count_matches", "not loaded"), dims=s_.get("dimensions"),
                                 receipts="\n".join(f"- {k}: {'ok' if r.get('ok') else 'FAILED ' + str(r.get('error') or r.get('skipped'))}" for k, r in receipts.items()),
                                 not_extracted=md.get("not_extracted"), failed=md.get("failed"))
        try:
            sp.atomic_write(os.path.join(out_dir, "PROCESS_REPORT.md"), text)
            receipts["report"] = {"ok": True}
        except OSError as exc:
            receipts["report"] = {"ok": False, "error": str(exc)}
            complete = False
    else:
        receipts["report"] = {"ok": False, "skipped": "library folder does not exist"}
        complete = False
    return {"complete": complete, "name": name, "failed_at": failed, "stages": receipts}


def refresh(name, cfg):
    """Re-run the derived stages (code nodes with variables, cards, scores) for a repo that is already in the library, after the tools improved. Copies, manifest, graph and the matrix are not touched."""
    rd = os.path.join(cfg.library, name)
    if not os.path.isdir(rd):
        raise ProcessRefused(f"{name} is not in the library")
    with open(cfg.matrix_path, encoding="utf-8") as fh:
        matrix = {r["repo"]: r for r in json.load(fh)}
    vpath = os.path.join(rd, "variables.jsonl")
    md = {**md_nodes.build_repo(name, cfg.library, cfg.md_out, matrix, variables_path=vpath), "variables_path": vpath}
    with vega_id.Crosswalk(os.path.join(cfg.one_plane, "crosswalk.db")) as cw:
        c = cards.build(name, cfg.library, cfg.one_plane, cw, matrix, cards.load_groups(None))
    kept = total = 0
    code = tests = docs = 0
    with open(os.path.join(rd, "INGEST_MANIFEST.csv"), encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            total += 1
            if row["disposition"] != "KEPT":
                continue
            kept += 1
            ext = os.path.splitext(row["detail"])[1].lower()
            code += ext in CODE_EXT
            tests += ext in CODE_EXT and bool(TEST_RX.search(row["detail"]))
            docs += ext in (".md", ".rst", ".txt")
    lib = {"kept": kept, "ledger_total": total, "code_files": code, "test_files": tests, "doc_files": docs}
    sc = stage_scores(cfg, name, lib, md, os.path.join(rd, "graphify-out", "graph.json"))
    return {"md_nodes": {k: md[k] for k in ("files", "symbols", "variables", "failed", "not_extracted")}, "cards": {k: c[k] for k in ("code_nodes", "files_with_nodes")}, "scores": sc["dimensions"]}


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("archive")
    ap.add_argument("--config", required=True)
    ap.add_argument("--name")
    ap.add_argument("--class", dest="cls")
    a = ap.parse_args(argv)
    rep = process(a.archive, Config.from_file(a.config), a.name, a.cls)
    print(json.dumps({"complete": rep["complete"], "name": rep["name"], "failed_at": rep["failed_at"], "stages": {k: ("ok" if v.get("ok") else v.get("error") or v.get("skipped")) for k, v in rep["stages"].items()}}, indent=1))
    return 0 if rep["complete"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
