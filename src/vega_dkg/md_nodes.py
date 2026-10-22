"""md_nodes.py - Tier 1 of the one plane: every code file as a markdown CODE NODE with per-symbol variables and scores.

One .md per source file under the output folder (<out>/<repo>/<path>.md). Front matter: vega_id, repo, path, language, license class, use boundary, taint flag, file scores,
dna_hash. Body: one section per symbol with its span, variables (names with write/read counts), calls, and measured scores, plus WEAKNESS and STRENGTH flags with the
components shown beside them. NO SOURCE TEXT is copied: a node holds structure, names and numbers only (a text_hash binds it to the file).

Honest limits (kept in every file's front matter as 'limits'):
  * variables and calls are read from the syntax tree; fan-in is matched BY NAME inside the repo, not resolved across imports
  * 'tested' means the symbol's name appears in a test file of the same repo, not that a test passes
  * scores are measurements, not a prediction that the code works. Prediction needs a contained run.
Languages: python (ast, precise), and tree-sitter (optional extra: pip install tree-sitter-language-pack) for javascript, typescript, tsx, java, go, c_sharp, c, cpp, rust, ruby, php,
kotlin. Other languages: a file-level node with size and 'symbols: not_extracted' (unbacked is not false).

Safety (the repos are untrusted input): a repo name must be one plain path component; every manifest path is resolved and refused if it leaves the repo folder (reading) or the
output folder (writing), symlinks included; files over MAX_FILE_BYTES are listed as not_extracted instead of being parsed; symbol names are cleaned before they enter the markdown
so a hostile name cannot add fake sections or fake fields for the combine finder to read; output files are written atomically.

  build_repo(repo, lib_root, out_root, matrix) ; python -m vega_dkg.md_nodes --lib LIB --out OUT --matrix repo_use_matrix.json REPO [REPO ...]"""
import ast
import csv
import hashlib
import io
import json
import os
import re

from vega_dkg import safe_paths as sp
from vega_dkg import vega_id as vid

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_REPO_BYTES = 400 * 1024 * 1024
MAX_MANIFEST_BYTES = 200 * 1024 * 1024
MAX_NAME = 200

LANG = {".py": "python", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".mts": "typescript", ".cts": "typescript", ".ts": "typescript", ".tsx": "tsx", ".java": "java",
        ".go": "go", ".cs": "c_sharp", ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".hpp": "cpp", ".rs": "rust", ".rb": "ruby", ".php": "php", ".kt": "kotlin"}
# tree-sitter node types per language: (symbol kinds, variable declarators, call kinds, branch kinds, handler kinds, comment kinds)
TS = {
    "javascript": (("function_declaration", "method_definition", "class_declaration", "generator_function_declaration"), ("variable_declarator",), ("call_expression",),
                   ("if_statement", "for_statement", "for_in_statement", "while_statement", "switch_case", "catch_clause", "ternary_expression", "do_statement"), ("try_statement", "catch_clause"), ("comment",)),
    "go": (("function_declaration", "method_declaration"), ("var_spec", "short_var_declaration"), ("call_expression",),
           ("if_statement", "for_statement", "expression_case", "type_case", "select_statement"), ("defer_statement",), ("comment",)),
    "java": (("method_declaration", "constructor_declaration", "class_declaration", "interface_declaration"), ("variable_declarator",), ("method_invocation",),
             ("if_statement", "for_statement", "enhanced_for_statement", "while_statement", "switch_label", "catch_clause", "ternary_expression"), ("try_statement", "catch_clause"), ("line_comment", "block_comment")),
    "c_sharp": (("method_declaration", "constructor_declaration", "class_declaration", "interface_declaration"), ("variable_declarator",), ("invocation_expression",),
                ("if_statement", "for_statement", "foreach_statement", "while_statement", "switch_section", "catch_clause"), ("try_statement", "catch_clause"), ("comment",)),
    "c": (("function_definition",), ("init_declarator",), ("call_expression",), ("if_statement", "for_statement", "while_statement", "case_statement"), (), ("comment",)),
    "rust": (("function_item", "impl_item", "struct_item", "trait_item"), ("let_declaration",), ("call_expression", "macro_invocation"), ("if_expression", "for_expression", "while_expression", "match_arm"), (), ("line_comment", "block_comment")),
    "ruby": (("method", "class", "module"), ("assignment",), ("call",), ("if", "unless", "while", "for", "when"), ("rescue", "begin"), ("comment",)),
    "php": (("function_definition", "method_declaration", "class_declaration"), ("simple_parameter", "assignment_expression"), ("function_call_expression", "member_call_expression"), ("if_statement", "for_statement", "foreach_statement", "while_statement", "case_statement", "catch_clause"), ("try_statement", "catch_clause"), ("comment",)),
    "kotlin": (("function_declaration", "class_declaration"), ("property_declaration", "variable_declaration"), ("call_expression",), ("if_expression", "for_statement", "while_statement", "when_entry", "catch_block"), ("try_expression", "catch_block"), ("line_comment", "multiline_comment")),
}
TS["typescript"] = TS["tsx"] = TS["javascript"]
TS["cpp"] = TS["c"]
_parsers = {}


def parser_for(lang):
    if lang not in _parsers:
        from tree_sitter_language_pack import get_parser
        _parsers[lang] = get_parser(lang)
    return _parsers[lang]


def h(b):
    return hashlib.sha256(b).hexdigest()


# ------------------------------------------------------------------------------------------------ python (ast)
def py_symbols(src):
    tree = ast.parse(src)
    lines = src.splitlines()
    out = []

    def doc_before(node):
        return ast.get_docstring(node) is not None

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            kind = "class" if isinstance(node, ast.ClassDef) else "function"
            w, r, calls, branch, handler = {}, {}, set(), 0, False
            for n in ast.walk(node):
                if isinstance(n, ast.Name):
                    d = w if isinstance(n.ctx, (ast.Store, ast.Del)) else r
                    d[n.id] = d.get(n.id, 0) + 1
                elif isinstance(n, ast.Call):
                    f = n.func
                    callee = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else None)
                    if callee:                                       # a call through an index, a call result or a lambda has no name: it is not recorded as a shared "?"
                        calls.add(callee)
                elif isinstance(n, (ast.If, ast.For, ast.While, ast.AsyncFor, ast.IfExp, ast.ExceptHandler, ast.comprehension, ast.BoolOp)):
                    branch += 1
                if isinstance(n, (ast.Try, getattr(ast, "TryStar", ast.Try))):
                    handler = True
            vars_ = {k: (w.get(k, 0), r.get(k, 0)) for k in sorted(set(w) | set(r))}
            end = getattr(node, "end_lineno", node.lineno)
            seg = "\n".join(lines[node.lineno - 1:end])
            out.append({"name": node.name, "kind": kind, "start": node.lineno, "end": end, "vars": vars_, "calls": sorted(calls), "branching": branch,
                        "error_handling": handler, "documented": doc_before(node), "todo": len(re.findall(r"TODO|FIXME|XXX", seg)),
                        "params": len(node.args.args) if kind == "function" else 0, "text_hash": h(seg.encode("utf-8", "replace"))})
    return out


# ------------------------------------------------------------------------------------------------ tree-sitter generic
def ts_symbols(src_bytes, lang):
    spec = TS[lang]
    sym_k, var_k, call_k, br_k, hd_k, cm_k = spec
    tree = parser_for(lang).parse(src_bytes)
    out = []
    comments = []

    def text(n):
        return src_bytes[n.start_byte:n.end_byte].decode("utf-8", "replace")

    def name_of(n):
        nm = n.child_by_field_name("name")
        if nm is not None:
            return text(nm)
        for c in n.children:
            if c.type in ("identifier", "property_identifier", "type_identifier", "field_identifier"):
                return text(c)
        return "<anonymous>"

    def collect_comments(n):
        if n.type in cm_k:
            comments.append((n.start_point[0], n.end_point[0]))
        for c in n.children:
            collect_comments(c)
    collect_comments(tree.root_node)
    cend = {e for _, e in comments}

    def walk_symbol(n):
        vars_, calls, branch, handler = {}, set(), 0, False
        stack = [n]
        while stack:
            x = stack.pop()
            if x.type in var_k:
                nm = x.child_by_field_name("name") or x.child_by_field_name("left") or (x.children[0] if x.children else None)
                if nm is not None and nm.type in ("identifier", "variable_name", "pattern", "field_identifier"):
                    t = text(nm)[:80]; vars_[t] = vars_.get(t, 0) + 1
            elif x.type in call_k:
                f = x.child_by_field_name("function") or x.child_by_field_name("name") or (x.children[0] if x.children else None)
                if f is not None:
                    callee = text(f).split("(")[0][-60:].strip()
                    if callee:
                        calls.add(callee)
            if x.type in br_k:
                branch += 1
            if x.type in hd_k:
                handler = True
            stack.extend(x.children)
        return vars_, sorted(calls), branch, handler

    def visit(n):
        if n.type in sym_k:
            v, c, b, hd = walk_symbol(n)
            seg = text(n)
            kind = "class" if "class" in n.type or n.type in ("struct_item", "trait_item", "impl_item", "interface_declaration", "module") else "function"
            out.append({"name": name_of(n), "kind": kind, "start": n.start_point[0] + 1, "end": n.end_point[0] + 1,
                        "vars": {k: (cnt, 0) for k, cnt in sorted(v.items())}, "calls": c, "branching": b, "error_handling": hd,
                        "documented": (n.start_point[0] - 1) in cend or (n.start_point[0]) in cend, "todo": len(re.findall(r"TODO|FIXME|XXX", seg)),
                        "params": 0, "text_hash": h(seg.encode("utf-8", "replace"))})
        for c in n.children:
            visit(c)
    visit(tree.root_node)
    return out


# ------------------------------------------------------------------------------------------------ scoring
def score(sym, fan_in, tested):
    size = sym["end"] - sym["start"] + 1
    weak, strong = [], []
    if sym["kind"] == "function":
        if not sym["error_handling"] and len(sym["calls"]) >= 3:
            weak.append("no error handling (%d calls, no try/handler)" % len(sym["calls"]))
        else:
            if sym["error_handling"]:
                strong.append("handles errors")
        if size > 80:
            weak.append("long (%d lines)" % size)
        elif size <= 40:
            strong.append("small (%d lines)" % size)
        if sym["branching"] > 15:
            weak.append("high branching (%d)" % sym["branching"])
        elif sym["branching"] <= 5:
            strong.append("low branching (%d)" % sym["branching"])
    if not sym["documented"]:
        weak.append("undocumented")
    else:
        strong.append("documented")
    if not tested:
        weak.append("name not referenced by any test file in the repo")
    else:
        strong.append("name referenced by a test file")
    if sym["todo"]:
        weak.append("%d TODO/FIXME markers" % sym["todo"])
    if fan_in >= 2:
        strong.append("reused (name called %d times in the repo)" % fan_in)
    return {"size_lines": size, "branching": sym["branching"], "variables": len(sym["vars"]), "calls_out": len(sym["calls"]), "fan_in_by_name": fan_in,
            "documented": sym["documented"], "error_handling": sym["error_handling"], "tested_by_name": tested}, weak, strong


def clean(s, limit=MAX_NAME):
    """A name as it may appear in the markdown: printable, no backticks, no line breaks, bounded. Applied to every name that is written."""
    s = "" if s is None else str(s)
    return re.sub(r"[`\x00-\x1f\x7f]", "_", s)[:limit]


def render(front, syms, scored):
    L = ["---"]
    for k, v in front.items():
        L.append("%s: %s" % (re.sub(r"\W", "_", str(k)), json.dumps(v, ensure_ascii=False)))
    L.append("---\n")
    L.append("# %s\n" % clean(front["path"], 1000))
    for s, (sc, weak, strong, vid_) in zip(syms, scored):
        L.append("## %s `%s` L%d-%d  (%s)" % (clean(s["kind"]), clean(s["name"]), s["start"], s["end"], vid_))
        L.append("- scores: " + ", ".join("%s=%s" % kv for kv in sc.items()))
        L.append("- weaknesses: " + ("; ".join(weak) if weak else "none measured"))
        L.append("- strengths: " + ("; ".join(strong) if strong else "none measured"))
        if s["vars"]:
            L.append("- variables (writes/reads): " + ", ".join("%s(%d/%d)" % (clean(k, 80), w, r) for k, (w, r) in list(s["vars"].items())))
        if s["calls"]:
            L.append("- calls: " + ", ".join(clean(c, 80) for c in s["calls"]))
        L.append("- text_hash: " + s["text_hash"] + "\n")
    return "\n".join(L) + "\n"


def load_matrix(path):
    with open(path, encoding="utf-8") as fh:
        rows = json.load(fh)
    if not isinstance(rows, list):
        raise sp.PathRefused("the use matrix is a list of repo rows")
    return {r["repo"]: r for r in rows if isinstance(r, dict) and isinstance(r.get("repo"), str)}


def build_repo(repo, lib_root, out_root, matrix, variables_path=None):
    sp.safe_name(repo)
    rd = sp.contained(lib_root, repo)
    row = matrix.get(repo, {})
    mp = os.path.join(rd, "INGEST_MANIFEST.csv")
    if not os.path.exists(mp):
        return {"repo": repo, "error": "no manifest"}
    raw = sp.read_capped(mp, MAX_MANIFEST_BYTES).decode("utf-8", "replace")
    files = [r for r in csv.DictReader(io.StringIO(raw, newline="")) if r.get("disposition") == "KEPT" and isinstance(r.get("detail"), str)]
    code = [(r, LANG[os.path.splitext(r["detail"])[1].lower()]) for r in files if os.path.splitext(r["detail"])[1].lower() in LANG]
    texts, test_blob, total, refused = {}, [], 0, []
    for r, lang in code:
        try:
            p = sp.contained(rd, r["detail"])
            size = os.path.getsize(p)
            if size > MAX_FILE_BYTES:
                texts[r["detail"]] = (None, lang, size)
                continue
            if total + size > MAX_REPO_BYTES:
                refused.append({"path": r["detail"], "reason": "repo byte budget used up"})
                continue
            b = sp.read_capped(p, MAX_FILE_BYTES)
        except (OSError, sp.PathRefused) as exc:
            refused.append({"path": r["detail"], "reason": type(exc).__name__ if isinstance(exc, OSError) else str(exc)})
            continue
        total += len(b)
        texts[r["detail"]] = (b, lang, len(b))
        if re.search(r"(^|[\\/_.-])(test|tests|spec)([\\/_.-]|$)", r["detail"].lower()):
            test_blob.append(b.decode("utf-8", "replace"))
    test_ids = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", "\n".join(test_blob)))
    parsed, calls_all = {}, {}
    stats = {"files": 0, "failed": 0, "symbols": 0, "not_extracted": 0, "refused": refused}
    for path, (b, lang, _size) in texts.items():
        if b is None:
            parsed[path] = None
            continue
        try:
            syms = py_symbols(b.decode("utf-8-sig", "replace")) if lang == "python" else ts_symbols(b, lang)
        except Exception:  # reviewed: a file that cannot be parsed (hostile nesting, bad syntax, missing parser) becomes a not_extracted node, never a crash
            syms = None
            stats["failed"] += 1
        parsed[path] = syms
        for s in syms or []:
            for c in s["calls"]:
                calls_all[c.split(".")[-1]] = calls_all.get(c.split(".")[-1], 0) + 1
    out_repo = sp.contained(out_root, repo)
    var_rows = []
    for path, syms in parsed.items():
        lang, size = texts[path][1], texts[path][2]
        rel = path.replace("\\", "/")
        front = {"vega_id": vid.vega_id(repo, rel, "md_code_node", rel, "", 0), "repo": repo, "path": rel, "language": lang,
                 "license_class": row.get("license_class", "UNKNOWN"), "use_boundary": row.get("personal_build") if row.get("personal_build") is not None else "not_scored",
                 "public_build": row.get("public_build") if row.get("public_build") is not None else "not_scored",
                 "tainted_if_used": row.get("taint_if_used", True), "bytes": size, "symbols": len(syms) if syms is not None else "not_extracted",
                 "limits": "fan-in by name only; tested = name appears in a test file; scores are measurements, not a prediction"}
        scored = []
        for s in syms or []:
            fan = calls_all.get(s["name"], 0)
            tested = (s["name"] in test_ids) if s["name"] != "<anonymous>" else False
            sc, weak, strong = score(s, fan, tested)
            sym_id = vid.vega_id(repo, rel, "md_symbol", s["name"], "L%d" % s["start"], 0)
            scored.append((sc, weak, strong, sym_id))
            for vname, (w, r) in s["vars"].items():
                var_rows.append({"variable_id": vid.vega_id(repo, rel, "md_variable", s["name"] + "." + vname, "L%d" % s["start"], 0), "repo": repo, "path": rel, "symbol": clean(s["name"]),
                                 "symbol_vega_id": sym_id, "variable": clean(vname, 200), "writes": w, "reads": r, "usage": w + r,
                                 "role": "write_only" if r == 0 and w else ("read_only" if w == 0 else "read_write"),
                                 "symbol_weaknesses": len(weak), "symbol_strengths": len(strong), "symbol_fan_in": sc["fan_in_by_name"], "symbol_tested": sc["tested_by_name"]})
        front["dna_hash"] = h(json.dumps([front, [x[0] for x in scored]], sort_keys=True, default=str).encode())
        dst = sp.contained(out_repo, rel + ".md")
        sp.atomic_write(dst, render(front, syms or [], scored))
        stats["files"] += 1
        stats["symbols"] += len(syms or [])
        stats["not_extracted"] += 1 if syms is None else 0
    if variables_path:
        sp.atomic_write(variables_path, "".join(json.dumps(v, sort_keys=True) + "\n" for v in var_rows))
    stats["variables"] = len(var_rows)
    stats["repo"] = repo
    stats["license_class"] = row.get("license_class")
    return stats


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--lib", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--matrix", required=True)
    ap.add_argument("repos", nargs="*")
    a = ap.parse_args(argv)
    matrix = load_matrix(a.matrix)
    repos = a.repos or sorted(matrix)
    os.makedirs(a.out, exist_ok=True)
    logp = os.path.join(a.out, "_build_log.jsonl")
    done = set()
    if os.path.exists(logp):
        with open(logp, encoding="utf-8") as fh:
            for ln in fh:
                try:
                    j = json.loads(ln)
                    if "error" not in j:
                        done.add(j["repo"])
                except ValueError:
                    continue  # reviewed: a damaged log line only means that repo is built again
    for r in repos:
        if r in done:
            continue
        try:
            s = build_repo(r, a.lib, a.out, matrix)
        except Exception as e:  # reviewed: one repo failing is logged and the run continues with the next
            s = {"repo": r, "error": type(e).__name__ + ": " + str(e)}
        with open(logp, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(s) + "\n")
        print(s, flush=True)


if __name__ == "__main__":
    main()
