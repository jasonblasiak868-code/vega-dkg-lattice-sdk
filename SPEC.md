# vega-dkg-lattice-sdk — Specification

Spec v1.0 — 2026-10-19 — describes the published reference implementation as tested; where this document and the source disagree, the source wins.

## 1. Purpose and scope

This specification covers the vega-dkg-lattice-sdk package (layer 7: knowledge). It defines the knowledge graph layer: every fact carries its origin and licence. The SDK builds the graph from (a) a repo library — code nodes, repo/doc cards, crosswalk IDs — and (b) offline CC0 public knowledge sources (Wikidata, OpenAlex, arXiv metadata). The predictive lattice side (routing, forecasting, fidelity) is explicitly out of scope — it lives in vega-reasoning-sdk `predict.py` and the galaxy repo.

In scope: cross-layer node IDs, repo/code/doc cards, markdown code nodes with per-symbol scores and variables, combination hypotheses, graph-fact candidate verification, safe path rules, CC0 knowledge import with commitment-gated loading, end-to-end repo processing pipeline, library improvement catalog.

Out of scope: model inference, training, reasoning pipelines, predictive forecasting, any network calls, any execution of third-party code, legal advice on licence interpretation.

## 2. Vocabulary

- **vega_id (vn1_)**: A deterministic cross-layer node identifier: `vn1_` + first 26 hex of SHA-256(universe | path | kind | label | location | ordinal). Same logical node across layers gets the same ID; duplicates are never merged — they get separate IDs and are flagged with `collision_group > 1`.
- **Crosswalk**: SQLite mapping layer + local_id → vega_id. Write-once; a later row for the same layer + local_id with different content is reported as a conflict, never silently ignored.
- **Repo node / code node / doc node**: Card kinds. Repo node = one per library repo (licence class, audit status, scores). Code node = one per graph node (vega_id, kind, label, path, location, degree, edge confidence, inherited licence/taint, DNA hash). Doc node = one per KEPT file in INGEST_MANIFEST.csv (sha256, path, linked code node count).
- **DNA hash**: SHA-256 of the card's JSON (sorted keys). Tamper evidence for each card.
- **Markdown code node**: One .md file per source file. Front matter: vega_id, repo, path, language, licence class, use boundary, taint flag, file scores, DNA hash. Body: one section per symbol (span, variables with write/read counts, calls, measured scores, WEAKNESS/STRENGTH flags). No source text is copied.
- **Combination hypothesis**: A HYPOTHESIS card pairing a weak symbol (missing error handling, undocumented, long, high branching) with a strong complement (same language, overlapping calls, similar size). Ranked by call overlap, size fit, reuse, cross-repo bonus. Carries strictest parent licence class and taint flag. Never a prediction that merged code works.
- **Candidate verification**: Five graph-fact criteria (c1 PERMISSIVE licence, c2 audit COMPLETE, c3 test_share_of_code ≥ 0.05, c4 degree ≥ 2, c5 extracted-edge share ≥ 0.5). A combination is verified through both parents; the weaker parent decides; the combination itself never passes.
- **Safe paths**: Plain-name check, containment (must resolve inside allowed root), size caps, atomic write (temp file + rename). Re-exports `vega_custody.safepaths`.
- **Knowledge import batch**: A set of parts (≤ 90 MB each, hard limit 100 MB) written from a downloaded dump, with a manifest (part hashes, counts) and one batch SHA-256 over the part list. Load only runs under a human commitment for that exact batch hash and counts; count-back verifies sent == stored == manifest.
- **Process DAG**: Hash-chained receipt for every stage of `process.process`. One entry per repo; records which stages passed/failed.

## 3. Components

### 3.1 vega_id.py
**Role**: Deterministic cross-layer node IDs and a conflict-reporting crosswalk.
**Public interface**:
- `vega_id(universe, path, kind, label, location, ordinal=0) -> str`
- `Crosswalk(path)`: `add_many(layer, rows) -> report`, `lookup(layer, local_id) -> str|None`, `stats() -> list`
- `IdRefused` exception
**Behavior**: `add_many` sorts by local_id, checks for existing rows, assigns ordinals per (universe,path,kind,label,location) tuple, inserts in a transaction. On conflict (same local_id, different content) reports the conflict and keeps the original. On failure rolls back. `lookup` returns the stored vega_id or None.
**Invariants**: IDs are deterministic for the same input tuple. Crosswalk is append-only for new local_ids; existing rows are never overwritten. Ordinals continue across calls (stored count used as base). Separator safety: `|` and `%` escaped before join.

### 3.2 cards.py
**Role**: Build repo, code, and doc cards for a library, read-only over the library with safe paths and atomic writes.
**Public interface**:
- `build(repo, lib_root, out_root, crosswalk, matrix, groups) -> coverage_row`
- `load_groups(path) -> dict`
- `main(argv=None)` CLI
**Behavior**: Reads repo's `verify.json`, `score.json`, `graphify-out/graph.json`, `INGEST_MANIFEST.csv`. Crosswalk assigns vega_ids to graph nodes. Computes degree and mean edge confidence per node. Builds repo_node (first line), then doc_nodes, then code_nodes; each gets a DNA hash. Writes `<out>/cards/<repo>.jsonl` atomically. Updates `coverage.json` atomically. One repo failure is recorded in full and the run continues.
**Invariants**: Card file is JSONL, first line is repo_node. Every card has a DNA hash. Licence inheritance flows from matrix row → repo_node → child nodes. `not_scored` placeholder for unbacked fields (kinetic_energy, scorer_outputs). Skipped files are recorded, never read.

### 3.3 md_nodes.py
**Role**: Produce one markdown code node per source file with per-symbol variables and measured scores; no source text.
**Public interface**:
- `build_repo(repo, lib_root, out_root, matrix, variables_path=None) -> stats`
- `load_matrix(path) -> dict`
- `main(argv=None)` CLI
**Behavior**: Reads `INGEST_MANIFEST.csv`, filters KEPT files. Python via `ast`; other languages via optional `tree-sitter-language-pack`. Files over 2 MB → `not_extracted`. Repo byte budget 400 MB. Test file detection by path regex. For each symbol: computes variables (write/read counts), calls, branching, error handling, documented, TODO count, fan-in by name, tested by name in test files. Scores: size, branching, variables, calls_out, fan_in, documented, error_handling, tested_by_name. Weaknesses/strengths derived from scores. Renders markdown with front matter and per-symbol sections. Writes atomically. Variables written to `variables.jsonl` (one row per variable with role, owning symbol's vega_id, strengths/weaknesses).
**Invariants**: No source text in output (only text_hash binds to file). Names cleaned (no backticks, control chars, bounded). File reads/writes via safe_paths. A parse failure → `not_extracted` node, not a crash.

### 3.4 combine_finder.py
**Role**: Propose cherry-pick combinations from md code nodes as HYPOTHESIS cards only.
**Public interface**:
- `parse_node(path) -> dict|None`
- `load(repos, root) -> (nodes, report)`
- `propose(nodes, top=20, min_overlap=0.1, dims=None) -> list[card]`
- `main(argv=None)` CLI
**Behavior**: Loads .md nodes from repos under root (safe_paths, size cap 5 MB, malformed/unsafe counted in report). Indexes functions by shared call names. For each weak function (has weakness in COMPLEMENT map), finds partners with same language, overlapping calls (≥ min_overlap), different name. Scores by call overlap (0.45), size fit (0.25), reuse = tested + fan_in (0.30), cross-repo bonus (0.1). For each weak dimension the strong symbol complements, emits a HYPOTHESIS card with strictest licence class, tainted=True, needs contained run + tests + replay. Keeps top N by score (heap).
**Invariants**: Pool capped at 200,000 functions. Same-name pairs skipped (duplicate, not complement). Hypothesis card never claims the merge works. Licence class = strictest of two parents (via `use_gate.STRICT`). Taint always true.

### 3.5 candidate_verify.py
**Role**: Verify a library candidate against graph facts (cards), no model, no execution.
**Public interface**:
- `verify_node(repo, degree=None, cards) -> dict`
- `verify_candidate(c, cards) -> dict`
- `repo_facts(repo, cards) -> dict|None` (cached by mtime+size)
**Behavior**: Reads repo card (first line of `<cards>/<repo>.jsonl`). Five criteria: c1 license_class==PERMISSIVE, c2 audit_status==COMPLETE, c3 test_share_of_code ≥ 0.05 (Wilson lower bound), c4 degree ≥ 2 (unknown = not passed), c5 graph_edges_extracted_not_inferred ≥ 0.5. Score = passed/5 + up to 0.1 for degree. For combination hypothesis: verifies both parents, returns weaker parent's score, passes=False, why="combination is a hypothesis: needs a contained run". For locked_workflow: passes=False. Missing/unreadable card → passes=False, why="nothing verified".
**Invariants**: Non-numeric scores count as not passed. Cache invalidated on file mtime/size change. Path safety via safe_paths.

### 3.6 safe_paths.py
**Role**: Re-exports `vega_custody.safepaths` (`PathRefused`, `atomic_write`, `contained`, `read_capped`, `safe_name`) so existing imports keep working.

### 3.7 knowledge_import.py
**Role**: Grow the DKG from offline CC0 public knowledge (Wikidata, OpenAlex, arXiv metadata) in governed parts.
**Public interface**:
- `SOURCES` dict (wikidata, openalex, arxiv — all CC0-1.0, PERMISSIVE, taint=False)
- `Filter(qids, instance_of, languages, max_nodes)`
- `import_dump(path, source, out_dir, flt, max_part_bytes, stubs, max_ids) -> manifest`
- `verify_parts(manifest, out_dir) -> list[problem]`
- `batch_commit_params(manifest) -> dict` (what the human signs)
- `load(manifest, out_dir, loader, commit_check, batch_size=1000) -> dict`
- `ImportRefused` exception
**Behavior**: Reads dump line by line (plain, .gz, .bz2; Wikidata array-of-lines format). Adapter per source emits nodes + edges. Nodes: vega_id, label, inherited licence/taint, dna_hash, extracted=True. Edges: relation, src/dst vega_ids, references count, referenced flag. Parts roll over at max_part_bytes (≤ 90 MB default, ≤ 100 MB hard). Manifest lists parts with sha256, bytes, records; batch_sha256 over part list. Stubs for targets outside filter (kind=stub). Duplicates in dump counted, kept once. `verify_parts` re-hashes every part against manifest. `load` verifies parts, calls `commit_check(action, params)` which must return True for the exact batch params, then streams parts through loader, counts back sent==stored==manifest.
**Invariants**: No network calls. Wikipedia (share-alike) and WikiLeaks (provenance/legal) are not in SOURCES and raise ImportRefused. Record cap 2 MB; oversize records refused not cut. Part size limit cannot be raised past 100 MB. Count-back catches loader that loses or overreports records. Commitment is for exact batch hash + counts; any mismatch refuses.

### 3.8 process.py
**Role**: One workflow from archive to finished record with a receipt for every stage; first failure stops and reports exactly where.
**Public interface**:
- `process(archive, cfg, name=None, license_class=None) -> dict`
- `refresh(name, cfg) -> dict` (re-run derived stages for existing repo)
- `Config.from_file(path) -> Config`
- `main(argv=None)` CLI
**Behavior**: Stages in order: intake (archive hash, size, member safety), extract (unpack to new folder), vet (static read: licence files → strictest class, credential-shaped values, risky calls, installer scripts, secret-named files, outbound hosts), library (copy to library, INGEST_MANIFEST.csv, verify.json, matrix row), md_nodes (build_repo with variables.jsonl), graph (run external `graphify` tool), cards (build with crosswalk, fail on missing IDs/conflicts), scores (Wilson lower bounds on 6 dimensions + symbol aggregates), dkg_load (run loader, count-back graph nodes), dag (record PROCESS_REPO entry), report (PROCESS_REPORT.md). First failure stops subsequent stages (marked skipped). DAG entry recorded even on failure. Matrix row written only after library copy succeeds. Report written last so it can include all receipts.
**Invariants**: No half-done state reported as complete. Archive ≤ 4 GB, unpacked ≤ 8 GB, ratio ≤ 200×, members ≤ 200k. Unsafe member names (absolute, traversal, null) refused. Secret-named files (.env*) skipped, never read. Licence detection: strictest class wins (STRONG_COPYLEFT > WEAK_COPYLEFT > PERMISSIVE > NON_COMMERCIAL > NO_LICENSE_FILE). Vet verdict: flags → REVIEW_FLAGS else NO_RED_FLAGS_STATIC. DAG records every stage pass/fail. DKG load disabled → workflow never complete.

### 3.9 catalog.py
**Role**: Dissect the repo library into an itemized improvement catalog per capability.
**Public interface**:
- `build(library_root, md_root, matrix_path, groups_path, out_dir, top_repos=25, top_symbols=40) -> summary`
- `main(argv=None)` CLI
**Behavior**: Loads matrix, REPO_GROUPS.md. For each repo: tags by keyword evidence on name, group, README head, folder/file names (from manifest). Tag keeps evidence string. Route from licence class (PERMISSIVE=cherry-pick/adopt, WEAK_COPYLEFT=method reference/contained, STRONG_COPYLEFT=method reference only, NON_COMMERCIAL=quarantine, NO_LICENSE_FILE=quarantine). Repo quality from score.json Wilson lower bounds. Symbol scoring: name/path match + tested + fan-in + strengths - weaknesses - test-file penalty. Output: LIBRARY_IMPROVEMENT_CATALOG.jsonl (every repo + every symbol) and .md (per capability: top repos, top symbols with license/sandbox/route/improves target).
**Invariants**: Keywords are a net, not a judgement. Scores measure structure, not fitness. Route is policy, not legal advice. Every repo classified (capability, domain, excluded personal, bundle, or NEEDS A READ). Bundles (folder hints) flagged for `vega_dkg.process` to open inner repos.

## 4. Guarantees and non-guarantees

### Guarantees

| Guarantee | Module | Test |
|---|---|---|
| Same logical node across layers gets identical vega_id | vega_id | test_dkg.py::Ids::test_same_logical_node_gets_same_id_in_two_layers |
| Crosswalk never silently overwrites; conflicts reported | vega_id | test_dkg.py::Ids::test_write_once |
| Crosswalk deterministic regardless of input order | vega_id | test_dkg.py::Ids::test_deterministic_regardless_of_input_order |
| Cards carry DNA hash; first line is repo_node | cards | test_dkg.py::Builders::test_cards_build_for_a_repo_with_a_graph |
| Markdown code nodes contain no source text | md_nodes | test_dkg.py::Builders::test_md_nodes_hold_no_source_text |
| Hypothesis card carries strictest parent licence + taint | combine_finder | test_dkg.py::Finder::test_no_overlap_no_pair_and_license_is_strictest_and_always_tainted |
| Combination never passes verification; weaker parent decides | candidate_verify | test_dkg.py::Verify::test_combination_is_never_passed_and_weaker_parent_decides |
| Knowledge import: every dump format reads same; bad/long lines counted not fatal | knowledge_import | test_knowledge_import.py::Reading::test_every_dump_format_reads_the_same, test_bad_lines_long_lines_blank_lines_and_a_byte_order_mark_are_counted_not_fatal |
| Parts roll over before size limit; manifest adds up; tampering caught | knowledge_import | test_knowledge_import.py::Parts::test_parts_roll_over_before_the_limit_and_the_manifest_adds_up, test_tampering_with_a_part_the_manifest_or_the_part_list_is_caught |
| Load refuses without approving commitment for exact batch; count-back enforced | knowledge_import | test_knowledge_import.py::Loading::test_nothing_loads_without_an_approving_commitment_for_that_exact_batch, test_the_count_back_catches_a_loader_that_loses_or_overreports_records |
| Process workflow: every stage runs or first failure stops with receipt; never half-done | process | test_process.py::Workflow::test_every_stage_runs_and_the_report_says_complete, test_process.py::NeverHalfDone |
| Secret-named files skipped and never read | process | test_process.py::Workflow::test_the_secret_named_file_is_skipped_and_never_read |
| Mixed licence repos take strictest class | process | test_process.py::Workflow::test_the_license_is_read_and_a_mixed_repo_takes_the_strictest |

### Non-guarantees

| Non-guarantee | Why |
|---|---|
| Graph facts are not truth | Sources can be wrong (Wikidata is public-edited); records are claims by that source with their references |
| Scores do not predict code works | Wilson lower bounds on structure (docs, tests, connectedness); a high score ≠ correct behaviour |
| Vet is not proof of safety | Static read only; nothing executed |
| Licence classification is not legal advice | Strictest detected class flows forward; counsel decides build implications |
| Hypothesis cards are not tried merges | Ranked ideas only; contained run + tests + replay required to become candidate |
| Containment is process-level | safe_paths + bounded runner keep files in folder; no OS sandbox, no memory/net isolation |
| Multi-language extraction needs optional extra | tree-sitter-language-pack not installed by default; without it, non-Python = file-level node only |
| Predictive lattice not in this SDK | Routing, forecasting, fidelity live in vega-reasoning-sdk predict.py and galaxy repo |

## 5. Failure modes

| Failure mode | What happens | Test |
|---|---|---|
| Tampered card file | `verify_parts` catches sha256 mismatch; `load` refuses before any store | test_knowledge_import.py::Parts::test_tampering_with_a_part_the_manifest_or_the_part_list_is_caught |
| Missing/invalid repo card | `verify_node` returns passes=False, why="no usable card... nothing verified" | test_dkg.py::Verify::test_missing_card_verifies_nothing |
| Combination hypothesis presented as candidate | `verify_candidate` returns passes=False, score=weaker parent, why="combination is a hypothesis: needs a contained run" | test_dkg.py::Verify::test_combination_is_never_passed_and_weaker_parent_decides |
| Expired/already-used commitment | `commit_check` must return True for exact batch params; any other value → ImportRefused, nothing loaded | test_knowledge_import.py::Loading::test_nothing_loads_without_an_approving_commitment_for_that_exact_batch |
| Replay with wrong count | `load` count-back: sent≠expect or stored≠sent → ImportRefused | test_knowledge_import.py::Loading::test_the_count_back_catches_a_loader_that_loses_or_overreports_records |
| Archive member traversal | `stage_intake` refuses on `..`, absolute paths, null bytes | test_process.py (implicit in intake validation) |
| Vet finds credential-shaped files | Flagged in receipt; files listed; run continues unless later stage fails | test_process.py::Workflow::test_the_secret_named_file_is_skipped_and_never_read |
| DKG load count mismatch | `stage_dkg_load` refuses; workflow incomplete; report says failed at dkg_load | test_process.py::NeverHalfDone::test_a_loader_that_stores_the_wrong_count_means_not_complete_and_says_where |
| DKG load disabled in config | `stage_dkg_load` raises ProcessRefused; workflow never complete | test_process.py::NeverHalfDone::test_with_the_dkg_load_switched_off_the_workflow_is_never_called_complete |
| Process failure at any stage | Later stages marked skipped; DAG records what ran; report says INCOMPLETE: failed at <stage> | test_process.py::NeverHalfDone::test_a_failure_skips_everything_after_it_and_records_the_run |
| Duplicate repo name | `stage_library` refuses if library folder or matrix row exists | test_process.py::NeverHalfDone::test_a_repo_is_processed_once_per_name |

## 6. Dependencies and layer rules

Registry entry (verbatim from ORGANISM_MAP.md):
```
vega-dkg-lattice-sdk | 7 knowledge | custody
```

Code dependencies:
- vega-custody-sdk — capsules, DAG, safe paths, bounded processes (foundation, layer 0)
- vega-harness-sdk — `use_gate` licence classification (layer 6, used by combine_finder)

**Dependencies point down layers only, never up or sideways.** This repo (layer 7) depends on layer 0 (custody) and layer 6 (harness). It is consumed by layer 6 (harness predicted paths), layer 5 (librarian lessons), layer 11 (reasoning lattice), layer 14 (galaxy view). No dependency on layers 8-10, 12-13, 15.

## 7. Conformance

A third party can verify this implementation by running the test suite with the dependency `src/` folders on PYTHONPATH:

```bash
python -m pytest tests/ -v
```

**Passing means**: All 96 tests in 6 files pass. The implemented behaviour matches the specification above for the tested paths.

**Passing does NOT mean**:
- The crypto is expert-reviewed (it is not).
- The vet stage proves runtime safety (it is a static read).
- Scores predict code correctness (they measure structure).
- Hypothesis cards are validated merges (they are ranked ideas).
- The licence matrix is legal advice (it is policy).
- The predictive lattice is included (it is in vega-reasoning-sdk).
- The system is hardened for production (reference implementation only).
