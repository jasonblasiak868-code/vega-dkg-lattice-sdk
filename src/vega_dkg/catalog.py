"""catalog.py - dissect the repo library into an itemized improvement catalog: for each capability we care about, which repos and which concrete symbols could improve what we have, where they are, how
they could be built in (adopt whole, cherry-pick and stack, method reference, or clean-room only), what the license allows, whether it must run in the contained sandbox, and which of OUR repos it would improve.

Inputs are what the library already holds: the use matrix (license class and routes), REPO_GROUPS.md (the hand-curated group of each repo), each repo's card and score.json, and the markdown code nodes
(every symbol with measured strengths and weaknesses). Capability tagging is by keyword evidence on the repo name, its group, its README head and its symbol names; every tag keeps the evidence that caused it,
so a wrong tag can be seen and corrected. HONEST LIMITS: keywords are a net, not a judgement; a symbol's score measures structure (documented, tested, small, reused), not that it does the job; a license
route is policy, not legal advice.

  catalog.build(library_root, md_root, matrix_path, groups_path, out_dir) -> summary ; python -m vega_dkg.catalog --library L --md M --matrix X.json --groups G.md --out DIR"""
import json
import os
import re

from vega_custody import safepaths as sp

CAPABILITIES = {
    "context_engineering": r"context[- ]engineer|context window|context (compress|manage|assembl|pack)|prompt cach|token budget|context graph|long[- ]context|compaction|summariz",
    "prompt_engineering": r"prompt[- ]engineer|prompt (templat|optim|library|compil)|system prompt|few[- ]shot|chain[- ]of[- ]thought|dspy|instruction tuning",
    "models_and_training": r"fine[- ]?tun|lora|qlora|rlhf|grpo|(?<![A-Za-z0-9])ppo(?![A-Za-z0-9])|quantiz|gguf|llama\.cpp|inference engine|vllm|ollama|model (serving|zoo|weights)|training (loop|pipeline|recipe)|unsloth|transformers",
    "agent_harness_and_orchestration": r"agent harness|harness|orchestrat|multi[- ]agent|agent (runtime|framework|loop)|swarm|workflow engine|planner|executor|subagent|coding agent",
    "mcp_and_tooling": r"(?<![A-Za-z0-9])mcp(?![A-Za-z0-9])|model context protocol|tool[- ]use|function calling|tool registry|plugin|skills?\b|toolkit|cli tool",
    "loop_engineering": r"self[- ]improv|feedback loop|reflexion|agent loop|eval(uation)? loop|autoresearch|recursive|(?<![A-Za-z0-9])rsi(?![A-Za-z0-9])|homeostasis|closed[- ]loop|iterat(e|ive) (refine|improv)",
    "graph_engineering": r"knowledge graph|code ?graph|graphrag|graph (database|neural|rag|embedding)|neo4j|networkx|ontology|repo ?graph|call graph|tree[- ]sitter",
    "memory": r"long[- ]term memory|agent memory|memory (layer|store|system)|vector (store|database|search)|(?<![A-Za-z0-9])rag(?![A-Za-z0-9])|retrieval|embedding|episodic|semantic memory|mem0|letta|zep",
    "evaluation_and_scoring": r"evaluat|benchmark|(?<![A-Za-z0-9])eval(?![A-Za-z0-9])|metric|scoring|leaderboard|test harness|llm[- ]as[- ]judge|regression test|red[- ]?team",
    "sandbox_and_security": r"sandbox|isolation|guardrail|prompt injection|secret scan|credential|policy engine|permission|least privilege|firecracker|gvisor|seccomp|containment|audit log",
    "ui_and_ux": r"design system|component library|dashboard|react|tailwind|ui kit|frontend|(?<![A-Za-z0-9])ux(?![A-Za-z0-9])|visuali[sz]",
    "data_pipelines_and_ingest": r"ingest|etl|scrap(e|ing)|crawler|document (parse|convert)|pdf|ocr|chunking|dataset",
}
DOMAIN = {"Trading, finance & markets": "domain: trading and finance (not a platform capability; kept for reference)", "Patent, legal & IP tools": "domain: patent and legal tooling (feeds ARGUS and the prosecution engine)",
          "VEGA own builds & IP packages": "owner's own build (already ours: review for what to fold into the SDK repos)", "Flutter / Dart framework family": "domain: Flutter and Dart framework family",
          "PERSONAL / NOT A REPO (exclude from DKG & any upload)": "EXCLUDED: personal material, never uploaded or used", "BUNDLES of zips (inner repos NOT yet opened)": "BUNDLE: inner repos not yet opened, open and process them with vega_dkg.process",
          "Extraction scratch (duplicates of the above)": "duplicate scratch copy of another repo"}
BUNDLE_HINT = re.compile(r"^(Codebase_Intelligence|Developer_experience|Elite_Frameworks|Framework_and_platform|IP_master|agenistic|agents_test|aimming|execution_pipeline|file_shell|governance_saf|make_your_own|model_conttext|provider_adapters|repo_intell|vega_code|what_vega|patent_repos|vega_compiler)", re.I)
TARGET = {"context_engineering": "vega-harness-sdk (reasoning_pipeline, prompt layers)", "prompt_engineering": "vega-harness-sdk (reasoning_pipeline) and the arsenal",
          "models_and_training": "vega-train-sdk (new trainers) and the Models tab", "agent_harness_and_orchestration": "vega-harness-sdk (Conductor) and vega-two-gate-sdk",
          "mcp_and_tooling": "vega-harness-sdk arsenal and vega-pareah-sdk adapters", "loop_engineering": "vega-harness-sdk (predicted_path, loop engine to be built)",
          "graph_engineering": "vega-dkg-lattice-sdk", "memory": "vega-librarian-sdk", "evaluation_and_scoring": "vega-librarian-sdk and vega-harness-sdk (calibration)",
          "sandbox_and_security": "vega-two-gate-sdk and vega-pareah-sdk quarantine", "ui_and_ux": "Vega OS app (VEGA_TERMINAL_APP, DKG explorer, Kronos Portal)",
          "data_pipelines_and_ingest": "vega-dkg-lattice-sdk (process workflow)"}
SYM = re.compile(r"^## (function|class) `([^`\n]+)` L(\d+)-(\d+)  \((vn1_\w+)\)\n- scores: (.*)\n- weaknesses: (.*)\n- strengths: (.*)\n", re.M)
MAX_MD = 5 * 1024 * 1024
README_HEAD = 20000
GROUP_CAPS = {"Agent harnesses, runtimes & orchestration": ["agent_harness_and_orchestration", "loop_engineering"], "Agent skills, plugins & prompts": ["mcp_and_tooling", "prompt_engineering", "context_engineering"],
              "Code graph, memory & knowledge graphs": ["graph_engineering", "memory"], "LLM models, training & eval": ["models_and_training", "evaluation_and_scoring"], "MCP servers & protocol": ["mcp_and_tooling"],
              "Frontend, UI/UX & design": ["ui_and_ux"], "LLM apps, chat UIs & gateways": ["models_and_training", "ui_and_ux"], "Vision, OCR, speech & translation": ["data_pipelines_and_ingest"],
              "Dev infrastructure, policy & automation": ["sandbox_and_security"], "VEGA own builds & IP packages": [], "Patent, legal & IP tools": [], "Trading, finance & markets": []}


def load_groups(path):
    groups, cur = {}, None
    if path and os.path.isfile(path):
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("## "):
                    cur = re.sub(r"\s*\(\d+\)\s*$", "", line[3:].strip())
                elif line.startswith("- ") and cur:
                    groups[line[2:].strip()] = cur
    return groups


def readme_head(repo_dir, name):
    """The README's opening (first match, shallowest first, up to four folders deep: library repos are often nested name/name/name/README.md)."""
    best = None
    for dp, dn, fs in os.walk(repo_dir):
        depth = os.path.relpath(dp, repo_dir).count(os.sep) if dp != repo_dir else 0
        if depth > 4:
            dn[:] = []
            continue
        dn[:] = [d for d in dn if d not in ("node_modules", ".git", "graphify-out")]
        for f in fs:
            if f.lower() in ("readme.md", "readme.rst", "readme.txt", "readme"):
                if best is None or depth < best[0]:
                    best = (depth, os.path.join(dp, f))
        if best and best[0] <= depth:
            break
    if not best:
        return ""
    try:
        return sp.read_capped(best[1], 4 * 1024 * 1024)[:README_HEAD].decode("utf-8", "replace")
    except (OSError, sp.PathRefused):
        return ""


def path_text(repo_dir):
    """Directory and file names from the ingest manifest (evidence: a folder called memory/ or mcp/ says more than a README sentence). Paths only, never contents."""
    p = os.path.join(repo_dir, "INGEST_MANIFEST.csv")
    if not os.path.isfile(p):
        return ""
    try:
        raw = sp.read_capped(p, 200 * 1024 * 1024).decode("utf-8", "replace")
    except (OSError, sp.PathRefused):
        return ""
    parts = set()
    for line in raw.splitlines()[1:]:
        detail = line.rsplit(",", 1)[-1].replace("\\", "/")
        parts.update(x for x in detail.split("/")[:5] if x)
    return " ".join(sorted(parts))[:300_000]


def tag_repo(name, group, head, paths=""):
    """{capability: [evidence strings]} from the repo name, its curated group, its README head and its folder/file names."""
    out = {}
    for cap in GROUP_CAPS.get(group or "", []):
        out.setdefault(cap, []).append(f"group: {group}")
    for cap, rx in CAPABILITIES.items():
        c = re.compile(rx, re.I)
        for label, text in (("name", name), ("readme", head), ("paths", paths)):
            m = c.search(text)
            if m:
                out.setdefault(cap, []).append(f"{label}: {m.group(0)[:40]}")
    return out


def symbols_of(md_repo_dir):
    """Yield (rel_path, name, kind, start, end, vega_id, scores, weak, strong) for every symbol node of one repo."""
    for dp, _, fs in os.walk(md_repo_dir):
        for f in fs:
            if not f.endswith(".md"):
                continue
            p = os.path.join(dp, f)
            try:
                t = sp.read_capped(p, MAX_MD).decode("utf-8", "replace")
            except (OSError, sp.PathRefused):
                continue
            hm = re.search(r'^path: "(.*)"$', t, re.M)
            rel = json.loads('"%s"' % hm.group(1)) if hm else os.path.relpath(p, md_repo_dir)
            for m in SYM.finditer(t):
                kind, name, a, b, vid, sc, wk, st = m.groups()
                yield rel, name, kind, int(a), int(b), vid, sc, wk, st


def symbol_score(name, rel, sc, weak, strong, rx):
    hit = bool(rx.search(name) or rx.search(rel))
    if not hit:
        return 0.0
    tested = "tested_by_name=True" in sc
    fan = re.search(r"fan_in_by_name=(\d+)", sc)
    s = 1.0 + 0.5 * tested + 0.15 * min(int(fan.group(1)) if fan else 0, 6) + 0.1 * strong.count(";") - 0.15 * (0 if weak.startswith("none") else weak.count(";") + 1)
    if "test" in rel.lower() or name.lower().startswith("test"):
        s -= 0.8
    return round(max(s, 0.0), 3)


def route_for(row):
    cls = row.get("license_class", "NO_LICENSE_FILE")
    return {"PERMISSIVE": ("cherry-pick or adopt whole in contained use, attribution kept; any public release is clean-room under library policy", False),
            "WEAK_COPYLEFT": ("method reference or contained use; copying or linking can carry copyleft duties; clean-room for public", True),
            "STRONG_COPYLEFT": ("method reference only; reimplement clean-room from a specification; never into a public build", True),
            "NON_COMMERCIAL_OR_RESTRICTED": ("read in quarantine only; terms limit use", True),
            "NO_LICENSE_FILE": ("no license means no permission: quarantine read only; clean-room for anything public", True)}.get(cls, ("unknown class: treat as no permission", True))


def repo_quality(score_path):
    try:
        with open(score_path, encoding="utf-8") as fh:
            d = json.load(fh).get("dimensions", {})
    except (OSError, ValueError):
        return None, {}
    vals = {k: v.get("wilson_lower") for k, v in d.items() if isinstance(v, dict) and isinstance(v.get("wilson_lower"), (int, float))}
    return (round(sum(vals.values()) / len(vals), 3) if vals else None), vals


def build(library_root, md_root, matrix_path, groups_path, out_dir, top_repos=25, top_symbols=40):
    with open(matrix_path, encoding="utf-8") as fh:
        matrix = {r["repo"]: r for r in json.load(fh) if isinstance(r, dict) and "repo" in r}
    groups = load_groups(groups_path)
    os.makedirs(out_dir, exist_ok=True)
    repos, items = [], {c: [] for c in CAPABILITIES}
    rxs = {c: re.compile(rx, re.I) for c, rx in CAPABILITIES.items()}
    for name in sorted(os.listdir(library_root)):
        rd = os.path.join(library_root, name)
        if not os.path.isdir(rd):
            continue
        row = matrix.get(name, {})
        route, sandbox = route_for(row)
        tags = tag_repo(name, groups.get(name), readme_head(rd, name), path_text(rd))
        q, dims = repo_quality(os.path.join(rd, "score.json"))
        rec = {"repo": name, "group": groups.get(name), "classification": None, "license_class": row.get("license_class", "NOT_IN_MATRIX"), "route": route, "contained_sandbox_required": sandbox or row.get("license_class") is None,
               "quality": q, "dimensions": dims, "capabilities": tags, "location": rd}
        if tags:
            rec["classification"] = "capability: " + ", ".join(sorted(tags))
        elif groups.get(name) in DOMAIN:
            rec["classification"] = DOMAIN[groups[name]]
        elif BUNDLE_HINT.match(name) or not os.path.isdir(os.path.join(rd, name)):
            rec["classification"] = "BUNDLE or owner folder: a folder of material, not one repo; open it and process each inner repo (vega_dkg.process)"
        else:
            head = re.sub(r"\s+", " ", readme_head(rd, name))[:160]
            rec["classification"] = "NEEDS A READ: no capability evidence found by keyword. README begins: " + (head or "(no README)")
        repos.append(rec)
        md_dir = os.path.join(md_root, name)
        if tags and os.path.isdir(md_dir):
            syms = list(symbols_of(md_dir))
            for cap in tags:
                hits = sorted(((symbol_score(n, rel, sc, wk, st, rxs[cap]), rel, n, kind, a, b, vid) for rel, n, kind, a, b, vid, sc, wk, st in syms), reverse=True)[:8]
                basis = "name or path matches the capability"
                hits = [h for h in hits if h[0] > 0]
                if not hits:                                                     # tagged by group/README but no symbol names it: offer its best-built symbols, labelled as repo-level
                    basis = "repo-level: best-built symbols of a repo tagged for this capability"
                    hits = sorted(((symbol_score(n, rel, sc, wk, st, re.compile(".")), rel, n, kind, a, b, vid) for rel, n, kind, a, b, vid, sc, wk, st in syms if kind == "function"), reverse=True)[:3]
                for s, rel, n, kind, a, b, vid in hits:
                    if s > 0:
                        items[cap].append({"capability": cap, "score": s if basis.startswith("name") else round(s * 0.5, 3), "basis": basis, "repo": name, "path": rel, "symbol": n, "kind": kind, "lines": f"{a}-{b}",
                                           "vega_id": vid, "license_class": rec["license_class"], "route": route, "contained_sandbox_required": rec["contained_sandbox_required"], "improves": TARGET[cap]})
    with open(os.path.join(out_dir, "LIBRARY_IMPROVEMENT_CATALOG.jsonl"), "w", encoding="utf-8") as fh:
        for r in repos:
            fh.write(json.dumps({"type": "repo", **r}, sort_keys=True) + "\n")
        for cap in items:
            for it in sorted(items[cap], key=lambda x: -x["score"]):
                fh.write(json.dumps({"type": "symbol", **it}, sort_keys=True) + "\n")
    lines = ["# LIBRARY IMPROVEMENT CATALOG", "",
             f"{len(repos)} repos dissected, every one classified: {sum(1 for r in repos if r['capabilities'])} by capability, the rest as a named domain, an excluded personal folder, a bundle, or an explicit 'needs a read'.",
             f"{len(repos)} repos dissected. Per capability: the repos most worth adopting or learning from, then the concrete symbols (function or class) to cherry-pick, with where each lives, its license route and which of OUR repos it would improve.",
             "Full detail (every repo, every symbol kept) is in LIBRARY_IMPROVEMENT_CATALOG.jsonl. Tags are keyword evidence, scores measure structure: both are leads for a human to read, not verdicts.", ""]
    for cap in CAPABILITIES:
        members = [r for r in repos if cap in r["capabilities"]]
        members.sort(key=lambda r: (r["quality"] or 0, len(r["capabilities"][cap])), reverse=True)
        lines += [f"## {cap.replace('_', ' ')}  ({len(members)} repos, improves: {TARGET[cap]})", "", "| repo | license | route | quality | evidence |", "|---|---|---|---|---|"]
        for r in members[:top_repos]:
            lines.append(f"| {r['repo']} | {r['license_class']} | {'SANDBOX; ' if r['contained_sandbox_required'] else ''}{r['route'][:70]} | {r['quality']} | {'; '.join(r['capabilities'][cap][:2])} |")
        top = sorted(items[cap], key=lambda x: -x["score"])[:top_symbols]
        lines += ["", f"Top symbols to cherry-pick for {cap.replace('_', ' ')} (* = repo-level pick: tagged by group or README, not by the symbol's own name):", "", "| score | symbol | repo | file | license | sandbox |", "|---|---|---|---|---|---|"]
        for it in top:
            lines.append(f"| {it['score']}{'*' if it['basis'].startswith('repo') else ''} | `{it['symbol']}` ({it['kind']}) | {it['repo']} | {it['path']}:{it['lines']} | {it['license_class']} | {'yes' if it['contained_sandbox_required'] else 'recommended'} |")
        lines.append("")
    sp.atomic_write(os.path.join(out_dir, "LIBRARY_IMPROVEMENT_CATALOG.md"), "\n".join(lines) + "\n")
    lines2 = ["", "## Repos with no capability tag (every one is accounted for)", "", "| repo | classification |", "|---|---|"] + [f"| {r['repo']} | {r['classification']} |" for r in repos if not r["capabilities"]]
    with open(os.path.join(out_dir, "LIBRARY_IMPROVEMENT_CATALOG.md"), "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines2) + "\n")
    return {"unclassified": sum(1 for r in repos if not r["classification"]), "needs_a_read": sum(1 for r in repos if (r["classification"] or "").startswith("NEEDS A READ")), "repos": len(repos), "tagged": sum(1 for r in repos if r["capabilities"]), "symbols": sum(len(v) for v in items.values()), "by_capability": {c: sum(1 for r in repos if c in r["capabilities"]) for c in CAPABILITIES}}


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--library", required=True)
    ap.add_argument("--md", required=True)
    ap.add_argument("--matrix", required=True)
    ap.add_argument("--groups")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    print(json.dumps(build(a.library, a.md, a.matrix, a.groups, a.out), indent=1))


if __name__ == "__main__":
    main()
