# vega-dkg-lattice-sdk — Capability Inventory

Minute capability inventory for the knowledge graph layer (layer 7). Each entry: capability / why a policy-or-prompt-level approach structurally cannot provide it / where enforced in code / test demonstrating it / honest limit (PARTIAL split explicit).

---

## 1. Cross-layer deterministic node IDs (vn1_) with conflict-reporting crosswalk

**Capability**: One ID for the same logical node across every layer (supergraph, codegraphs, library, etc.); duplicates are never merged — they get separate IDs and are flagged `collision_group > 1`. A later row for the same `layer + local_id` with different content is reported as a conflict, never silently ignored.

**Why policy/prompt cannot provide it**: A model cannot enforce deterministic, collision-flagged identity across independent data sources. Prompt-level "use the same ID" has no mechanism to detect when two sources hand out the same local ID for different nodes, or when a source reuses an ID for changed content. The crosswalk is an append-only SQLite store with a unique index on `(layer, vega_id)` and a conflict check on `(layer, local_id)` content hash — this is structural enforcement, not a convention.

**Enforced in**: `vega_id.py` — `vega_id()` deterministic hash, `Crosswalk.add_many()` transaction with conflict reporting, `Crosswalk.stats()` collision groups.

**Test**: `test_dkg.py::Ids::test_same_logical_node_gets_same_id_in_two_layers`, `test_write_once`, `test_deterministic_regardless_of_input_order`, `test_duplicates_are_separate_ids_and_flagged_not_merged`.

**Honest limit**: IDs are deterministic for the same input tuple; different batching of the same layer produces different ordinals for duplicates (order-independent only within one `add_many` call). Crosswalk is local SQLite — no distributed consensus. Ordinals continue across calls using stored count, so two batches can never hand the same ID to two different nodes for the same logical tuple.

---

## 2. Repo, code, and doc cards with licence inheritance and DNA hashes

**Capability**: Three card kinds (repo_node, code_node, doc_node) written as JSONL. Every card carries a DNA hash (SHA-256 of sorted JSON). Licence class and taint flag flow from the use matrix → repo_node → child nodes. Code nodes inherit degree, mean edge confidence, and the strictest licence class. First line of each card file is the repo_node.

**Why policy/prompt cannot provide it**: A model prompted to "include licence info" can hallucinate, omit, or contradict itself across cards. The inheritance chain is structural: the matrix row is read once, the repo_node is written first with those fields, and every subsequent card copies `inherit = repo_node.inherit` verbatim. The DNA hash makes any post-hoc edit detectable without trusting the writer.

**Enforced in**: `cards.py` — `build()` reads matrix, verify.json, score.json, graph.json; crosswalk assigns vega_ids; computes degree/confidence; writes cards atomically with DNA hash on each.

**Test**: `test_dkg.py::Builders::test_cards_build_for_a_repo_with_a_graph` (checks repo_node first, code_node count, licence_class PERMISSIVE propagated).

**Honest limit**: Cards are only as true as the process that built them (vet, graphify, scoring). `kinetic_energy` and `scorer_outputs` are `not_scored` placeholders. Skipped files (secret-named, oversized) are recorded but never read — their absence is not proven. The licence class is the strictest detected by keyword rules, not a legal determination.

---

## 3. Markdown code nodes per source file: symbols, variables, scores, no source text

**Capability**: One `.md` file per source file under `<out>/<repo>/<path>.md`. Front matter: vega_id, repo, path, language, licence class, use boundary, taint flag, file scores, DNA hash. Body: one section per symbol (span, variables with write/read counts, calls, branching, error handling, documented, TODOs, fan-in by name, tested by name in test files). WEAKNESS/STRENGTH flags with components shown. NO SOURCE TEXT is copied — only a `text_hash` binds the node to the file.

**Why policy/prompt cannot provide it**: A model prompted to "extract symbols and scores" will copy source text, miss symbols, invent scores, or lose the variable write/read distinction. The extraction is structural: Python via `ast` (precise), other languages via tree-sitter grammars (optional extra). Variable roles (write_only, read_only, read_write) come from syntax tree context (`ast.Store` vs `ast.Load`), not heuristic. The `text_hash` binds the node to the exact file bytes without storing them.

**Enforced in**: `md_nodes.py` — `py_symbols()` (ast), `ts_symbols()` (tree-sitter), `score()` (Wilson components), `render()` (markdown with cleaned names), `build_repo()` (safe_paths, atomic write, repo byte budget 400 MB, file cap 2 MB).

**Test**: `test_dkg.py::Builders::test_md_nodes_round_trip_into_the_combine_finder` (3 symbols, 2 files, 0 failed), `test_md_nodes_hold_no_source_text` (asserts docstring and body text absent).

**Honest limit**: Fan-in is matched BY NAME inside the repo, not resolved across imports. `tested` means the symbol's name appears in a test file of the same repo, not that a test passes. Scores are measurements of structure, not a prediction that code works. Languages without a parser (or without `tree-sitter-language-pack` installed) get file-level nodes with `symbols: not_extracted`. Variable roles are intra-symbol only, not data-flow across files.

---

## 4. Combination hypotheses: weak symbol paired with strong complement

**Capability**: A HYPOTHESIS card pairing a weak symbol (no error handling, undocumented, long, high branching) with a strong complement (same language, overlapping calls, similar size). Ranked by call overlap (0.45), size fit (0.25), reuse = tested + fan_in (0.30), cross-repo bonus (0.1). Indexed by shared call names so cost grows with viable pairs, not square of all symbols. Every card carries the strictest parent licence class (via `use_gate.STRICT`), `tainted_if_used: true`, `public_build: "clean-room only"`, `needs: ["contained run", "tests that pass", "replay reproduces result hash"]`.

**Why policy/prompt cannot provide it**: A model prompted to "suggest a better version of this function" will generate new code, not point at an existing symbol in the library with measured strengths that complement measured weaknesses. The hypothesis is a *reference* to two existing symbols with provenance, licence inheritance, and a ranked score — not a generated merge. The index on shared calls and the heap of top-N keep it bounded and deterministic.

**Enforced in**: `combine_finder.py` — `parse_node()` (validates md structure), `load()` (safe_paths, size cap, report on skipped), `propose()` (COMPLEMENT map, call-index, scoring, strictest licence via `use_gate.klass_of`, heap of top N).

**Test**: `test_dkg.py::Finder::test_no_overlap_no_pair_and_license_is_strictest_and_always_tainted` (no overlap → empty; STRONG_COPYLEFT parent → strictest licence, tainted), `test_md_nodes_round_trip_into_the_combine_finder` (fetch/safe_fetch pair, fixes "no error handling", PERMISSIVE).

**Honest limit**: A hypothesis is a ranking of ideas, NOT a prediction that the merged code works. Call overlap is by name only, not signature compatibility. The "strong" symbol's strengths are measured structurally (error handling present, documented, small, low branching) — not that it actually handles errors correctly. Cross-repo pairs rank higher but licence may be stricter. The combination never passes candidate verification; it becomes a candidate only after a contained run passes tests and a replay reproduces the result hash.

---

## 5. Graph-fact candidate verification (5 criteria, combination never passes)

**Capability**: Verify a library candidate against repo card facts — no model, no execution. Five criteria: c1 license_class==PERMISSIVE, c2 audit_status==COMPLETE, c3 test_share_of_code ≥ 0.05 (Wilson lower bound), c4 degree ≥ 2 (unknown = not passed), c5 graph_edges_extracted_not_inferred ≥ 0.5. Score = passed/5 + up to 0.1 for degree. For a combination hypothesis: verifies both parents, returns weaker parent's score, `passes: false`, why="combination is a hypothesis: needs a contained run". Missing/unreadable card → passes=false, why="nothing verified".

**Why policy/prompt cannot provide it**: A model prompted to "check if this repo is safe to use" cannot reliably read the card file, compute Wilson lower bounds, check all five criteria, and refuse when any is missing. The verification is a deterministic function over stored facts with a cache invalidated on file mtime/size. The combination rule (weaker parent decides, combination never passes) is a hard structural gate — a prompt cannot enforce "never pass a combination on its own" without being tricked by a rephrased request.

**Enforced in**: `candidate_verify.py` — `verify_node()` (five criteria, score), `verify_candidate()` (dispatches to node or combination or locked_workflow), `repo_facts()` (cached by mtime+size, safe_paths).

**Test**: `test_dkg.py::Verify::test_all_five_pass`, `test_each_failure_is_named_and_unknown_degree_does_not_pass`, `test_missing_card_verifies_nothing`, `test_combination_is_never_passed_and_weaker_parent_decides`, `test_locked_workflow_is_not_graph_verifiable`.

**Honest limit**: Passing means the graph facts look sound, NOT that the code works. Non-numeric scores count as not passed (fail-closed). The card cache serves stale data only if the file mtime+size are unchanged — a malicious overwrite preserving both could fool it. Criteria are read from the card; the card's provenance is the vet/graphify/scoring pipeline, not re-derived here.

---

## 6. Safe path rules for untrusted repos (containment, size caps, atomic writes)

**Capability**: Every file read/write in the SDK goes through `safe_paths` (re-exports `vega_custody.safepaths`): `safe_name()` (plain component, no traversal), `contained(root, *parts)` (resolves inside root, refuses escape), `read_capped(path, max_bytes)` (refuses oversize), `atomic_write(path, data)` (temp file + fsync + rename). Used by cards, md_nodes, combine_finder, candidate_verify, knowledge_import, process, catalog.

**Why policy/prompt cannot provide it**: A model prompted to "only read files inside this folder" can be tricked by symlinks, relative paths, or encoding tricks. The enforcement is in the OS syscall layer: `contained` resolves the absolute path and checks `os.path.commonpath([root, resolved]) == root`; `read_capped` reads in chunks and refuses before loading the whole file; `atomic_write` guarantees the target either has the old content or the new content, never a partial write.

**Enforced in**: `safe_paths.py` (re-export), `vega_custody.safepaths` (actual implementation). Every module imports and uses these for all I/O.

**Test**: Implicit in every test that reads/writes files (all test files). Explicit in `test_knowledge_import.py::Parts` (part size limits, record cap), `test_process.py::Workflow` (secret-named skipped, archive member safety).

**Honest limit**: Containment is process-level, not an OS sandbox. It prevents directory traversal and oversize reads; it does not isolate memory, network, or syscalls. A compromised dependency in the same process could bypass it. Symlinks inside the root that point outside are followed by `os.path.realpath` in `contained` — the check is on the resolved path.

---

## 7. Offline CC0 knowledge import: Wikidata, OpenAlex, arXiv metadata

**Capability**: Read a downloaded dump (plain, .gz, .bz2; Wikidata array-of-lines format) line by line, never loading the whole file. Filter by qids, instance_of, languages, max_nodes. Emit nodes and edges in DKG card shape (vega_id, dna_hash, inherited licence/taint, extracted=True, references count). Write parts ≤ 90 MB (hard 100 MB) with manifest (part hashes, bytes, records) and one batch SHA-256 over the part list. Stubs for targets outside filter. Duplicates in dump counted, kept once. `verify_parts()` re-hashes every part against manifest. `load()` verifies parts, demands `commit_check(action, params) == True` for the exact batch hash and counts, streams through loader, counts back sent==stored==manifest.

**Why policy/prompt cannot provide it**: A model cannot stream a 100 GB dump line by line, enforce part size limits, compute a batch hash over the part list, and refuse to load without a human commitment for that exact batch. The commitment is a signed note from a human for *this exact batch* (source, batch_sha256, node count, edge count) — the model never holds the signing key. Count-back (sent==stored==manifest) catches a loader that loses or overreports records. Tampering with any part, the manifest, or the part list is caught by `verify_parts` before any load.

**Enforced in**: `knowledge_import.py` — `iter_json_lines()` (streaming, bad/long lines counted), `import_dump()` (adapters per source, PartWriter with rollover, manifest + batch_sha256), `verify_parts()` (re-hash), `batch_commit_params()` (what human signs), `load()` (verify → commit_check → stream → count-back).

**Test**: `test_knowledge_import.py::Reading` (every dump format same; bad/long/BOM lines counted), `Records` (nodes carry label/licence/taint/DNA hash; unreferenced kept, deprecated/valueless dropped; languages fall back; filters by qid/class/count; duplicates counted; IDs stable; edges point at real IDs via stubs), `OtherSources` (OpenAlex papers with citation/author edges, no abstract text; arXiv abstract hash not text; Wikipedia/WikiLeaks/unknown refused), `Parts` (rollover before limit, manifest adds up, tampering caught, 100 MB hard limit enforced, oversize record refused), `Loading` (commitment names exact batch; nothing loads without approving commitment; tampered part stops load before any store; count-back catches lose/overreport).

**Honest limit**: Sources can be wrong (Wikidata is public-edited) — records are claims by that source with their references, not truth. Wikipedia text (CC-BY-SA share-alike) and WikiLeaks (provenance/legal problems) are deliberately not imported; they would need separate adapters and the use gate. Entity formats change over time; unknown shapes are counted as skipped, never guessed. The module makes no network calls — you must download the dump first. Abstract text from arXiv is kept only as a hash and length; full text is not stored.

---

## 8. End-to-end repo processing: intake → extract → vet → library → md_nodes → graph → cards → scores → DAG → DKG load → report

**Capability**: One workflow from a zip archive to a finished record with a receipt for every stage. Either every stage passed and the report says COMPLETE, or the first failure stops it and the report says exactly which stage failed and which passed. No half-done state reported as done. Stages: intake (archive hash, size, member-name safety), extract (unpack to new folder), vet (static read: licence files → strictest class, credential-shaped values, risky calls, installer scripts, secret-named files, outbound hosts), library (copy to library, INGEST_MANIFEST.csv, verify.json, matrix row), md_nodes (build_repo with variables.jsonl), graph (external graphify tool), cards (build with crosswalk, fail on missing IDs/conflicts), scores (Wilson lower bounds on 6 dimensions + symbol aggregates), dkg_load (run loader, count-back graph nodes), dag (hash-chained PROCESS_REPO entry), report (PROCESS_REPORT.md).

**Why policy/prompt cannot provide it**: A model prompted to "process this repo" cannot enforce the atomicity of the pipeline (first failure stops, receipt for every stage, matrix row written only after library copy succeeds, DAG entry recorded even on failure). The vet is a static read with specific detectors (licence regex, credential regex, risky call regex, installer regex, host extraction) — a prompt cannot guarantee it runs the same detectors on every file. The DKG load count-back (stored nodes == graph nodes) is a hard numeric gate. The report is generated last so it can include every receipt.

**Enforced in**: `process.py` — `process()` driver with `run(stage, fn)` that marks subsequent stages skipped on first failure, `Config` dataclass, `stage_intake/extract/vet/library/md_nodes/graph/cards/scores/dkg_load/dag/report`, `refresh()` for derived stages only.

**Test**: `test_process.py::Workflow::test_every_stage_runs_and_the_report_says_complete`, `test_every_variable_is_a_scored_row`, `test_scores_hold_graph_and_variable_measures`, `test_the_secret_named_file_is_skipped_and_never_read`, `test_the_license_is_read_and_a_mixed_repo_takes_the_strictest`, `test_no_license_file_means_no_permission`, `NeverHalfDone::test_a_loader_that_stores_the_wrong_count_means_not_complete_and_says_where`, `test_with_the_dkg_load_switched_off_the_workflow_is_never_called_complete`, `test_a_failure_skips_everything_after_it_and_records_the_run`, `test_a_repo_is_processed_once_per_name`.

**Honest limit**: The vet is a static read, not proof of safety. Scores measure structure, not whether code works. The graph build calls an external `graphify` tool (not in this repo). DKG load requires a graph database instance and a loader script (not in this repo). Archive limits: 4 GB archive, 8 GB unpacked, 200× ratio, 200k members. Secret-named files (.env*) are skipped and never read — their content is unknown. Mixed licence repos take the strictest class (STRONG_COPYLEFT > WEAK_COPYLEFT > PERMISSIVE > NON_COMMERCIAL > NO_LICENSE_FILE). If DKG load is disabled in config, the workflow is NEVER complete.

---

## 9. Library improvement catalog: capability tagging, symbol scoring, licence route, target mapping

**Capability**: Dissect the repo library into an itemized catalog per capability. Tags by keyword evidence on repo name, curated group (REPO_GROUPS.md), README head, folder/file names (from manifest). Every tag keeps the evidence string. Route from licence class (PERMISSIVE=cherry-pick/adopt, WEAK_COPYLEFT=method reference/contained, STRONG_COPYLEFT=method reference only, NON_COMMERCIAL=quarantine, NO_LICENSE_FILE=quarantine). Repo quality from score.json Wilson lower bounds. Symbol scoring: name/path match + tested + fan-in + strengths - weaknesses - test-file penalty. Output: LIBRARY_IMPROVEMENT_CATALOG.jsonl (every repo + every symbol) and .md (per capability: top repos, top symbols with license/sandbox/route/improves target repo). Bundles (folder hints) flagged for `vega_dkg.process` to open inner repos.

**Why policy/prompt cannot provide it**: A model prompted to "categorize these repos" cannot keep the evidence string for every tag, compute the licence route from the strictest detected class, score symbols by structural measures (tested, fan-in, strengths/weaknesses), and map each capability to the specific Vega SDK repo it would improve. The catalogue is a deterministic transformation of the library's existing artifacts (matrix, groups, cards, md nodes) — not a judgement.

**Enforced in**: `catalog.py` — `CAPABILITIES` regex map, `GROUP_CAPS` group→capability, `DOMAIN` classifications, `TARGET` capability→Vega repo, `build()` (loads matrix/groups, tags each repo, scores symbols, writes jsonl + md).

**Test**: Integration covered by `test_dkg.py::Builders` flow (md_nodes → combine_finder → cards → candidate_verify uses the catalog's output artefacts). No dedicated unit test for catalog.py itself.

**Honest limit**: Keywords are a net, not a judgement — a repo tagged for "graph_engineering" may not actually have a usable graph. Scores measure structure, not fitness for purpose. Route is policy, not legal advice. Every repo gets a classification (capability, domain, excluded personal, bundle, or NEEDS A READ) — none are silently dropped. The catalog does not decide what to adopt; it presents leads for a human to read.

---

## This repo's part in the family predictive loop

The ORGANISM_MAP.md defines two flows that never mix:

**AUTHORITY FLOW (down from the human, never from the model)**:
human signs a single-use commitment → jacket gates check it → contained execution (two-gate) → the action touches the world → the record is written.

**DATA/KNOWLEDGE FLOW (up from the record)**:
custody records → librarian distils lessons → **dkg-lattice builds the knowledge graph (origin + licence per fact)** → reasoning/galaxy forecast from the lattice → harness pre-registers predicted paths → metacog gates completion on evidence → feed/galaxy show it all to the human, who decides again.

**This repo is the centerpiece of the knowledge step**. It produces the licence-aware knowledge graph that feeds foresight:

1. **Records** (custody SDK) → the append-only chain of what happened.
2. **Lessons** (librarian SDK) → distilled from records, stored as cards with provenance.
3. **Knowledge graph** (**this SDK**) → every fact (from repo library or CC0 public sources) carries its origin (which repo, which dump, which line) and its licence class (PERMISSIVE/WEAK_COPYLEFT/STRONG_COPYLEFT/NON_COMMERCIAL/NO_LICENSE_FILE) and taint flag. The crosswalk gives one ID per logical node across layers. Combination hypotheses propose improvements with strictest-parent licence inheritance. Candidate verification gates on graph facts (5 criteria).
4. **Lattice foresight** (reasoning SDK `predict.py`, galaxy SDK) → consumes this graph to forecast steps ahead, route, and compute fidelity. The predictive lattice side is NOT in this repo.
5. **Human decision** → the governance feed/galaxy show the graph + foresight; the human signs the next commitment.

**What this means for this repo**: Every capability above exists to make the knowledge graph trustworthy enough that the foresight layer can reason from it, and the human can verify it. The DNA hashes, licence inheritance, commitment-gated import, count-back loading, and combination hypothesis taint are not academic — they are what lets the foresight layer say "this path is forecast from facts with these licences and this provenance" without hallucination. The PARTIAL split (graph built, predictive lattice in reasoning SDK) is explicit: this repo stops at the graph; the forecasting is a separate concern owned by a separate SDK.

---

**Patent pending (U.S. provisional application 64/178,949 and others).** Draft licence text, not yet reviewed by an attorney.
