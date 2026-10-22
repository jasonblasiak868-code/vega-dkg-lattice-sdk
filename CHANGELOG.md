# Changelog

## 2026-10-21: fixes found by a line-by-line source read

Found by reading each module against the README and SPEC, then reproducing the suspected defect before fixing it. Each fix has a regression test that failed before the fix, and each fix was checked by undoing it and confirming a test fails.

### Batch 1: `vega_id`, `candidate_verify`, `cards`

#### Fixed
- **The same `local_id` twice in one `add_many` call aborted the whole batch** with a database integrity error. A repeat with the same content is now counted as unchanged; a repeat with different content is reported as a conflict and the first stands.
- **Two writers adding the same node at once: the second one failed.** Both read the same ordinal, and the unique index rejected the second write. The read-and-write now runs as one immediate transaction, so writers take turns.
- **The repo-card cache in `candidate_verify` grew without limit.** It now holds at most 256 cards and drops the oldest.
- **`cards.build` wrote an empty value for a policy field the use matrix did not have** (`personal_build`, `public_build`, `audit_policy`, `archive_sha256`), which reads like "no". They are now `not_scored`, as the module documents.
- **A manifest file in one folder borrowed the graph nodes of a same-named file at the top level**, which overstated coverage. The archive's top folder is now stripped only when every kept path shares it and no graph path starts with it.
- **Opening a brand-new crosswalk file from two processes at once could fail with "database is locked"** during setup. Setup now waits and retries.

### Batch 2: `combine_finder`, `catalog`, `md_nodes`

#### Fixed
- **A markdown file with no front matter, or front matter that did not open the file, could be read as a valid code node** (any text containing `---` twice). The front matter must now open the file and carry `path`, `repo` and `language`; otherwise the file is counted as malformed.
- **An unnamed callee (a call through an index, a call result or a lambda) was recorded as a call named `?`**, so every function making one looked like it shared a call with every other. Unnamed callees are no longer recorded, and a stray `?` or empty name in a node file is ignored.
- **A call name shared by thousands of functions made pairing cost a pair per function** (quadratic). A call name shared by more than 1,000 functions (`MAX_POSTING`) is no longer used to look for partners.
- **`propose` accepted nonsense arguments** (a text `min_overlap`, a string for `dims`, an unknown dimension) and quietly returned nothing. They are now refused with a clear message.
- **A repo listed twice was read twice**, doubling its nodes and hypotheses. It is read once.
- **One forged or damaged `path:` line stopped the whole catalog build** with a decoding error. The file's own relative path is used instead.
- **The catalog's two output files were written non-atomically** (one of them appended to after the first was moved into place). Both are now written once, atomically.
- **`md_nodes` wrote an empty value into the front matter for a policy field the use matrix did not have** (`use_boundary`, `public_build`). They are now `not_scored`.

### Batch 3: `process`, `knowledge_import`

#### Fixed
- **A vendored license could make a repo look licensed.** A license file in a subfolder (a dependency's MIT text) set the whole repo to PERMISSIVE when the repo had no license of its own. Only a license file at the repo root decides the class now; a subfolder license can make the class stricter, never more permissive, and the report flags "found only in subfolders".
- **A source file called `license_utils.py` was treated as a license file.** Only real license-file names (no source extensions) count.
- **Secret-named files (`.env*`) were copied into the library** even though the ledger said "skipped". They are now never copied; the ledger still lists each as `SKIPPED_SECRET`.
- **Two runs adding rows to the use matrix at once could lose a row.** The file is now re-read and written under a lock (`add_matrix_row`), and a repo that already has a row is refused.
- **The `provenance_completeness` score was always about 1** (kept files out of kept files). It now counts the kept files against every file the ledger saw, including the skipped secrets.
- **`refresh` counted manifest lines, not kept files.** It now counts the `KEPT` rows, as `process` does.
- **A `--class` override could be any text.** It must be one of the known classes.
- **A deeply nested JSON line crashed the whole import** (`RecursionError`). It is counted as a bad line.
- **A Wikidata record with an unexpected shape (claims as a list, labels as a list, statements as numbers) crashed the import.** It is counted as skipped.
- **An OpenAlex record whose `referenced_works` was text was read letter by letter into false citation edges.** It is ignored and counted.
- **OpenAlex `AUTHORED_BY` edges pointed at author ids that were never written.** Authors are now nodes.
- **A second import into the same folder overwrote the first batch's parts and manifest.** It is refused.
- **A record larger than the part limit was written into an oversized part.** It is refused.
- **The id limit ignored edge targets,** so memory could grow without bound on an unfiltered dump. Targets count against it.
- **A failing loader raised its own exception part-way through a load.** It is now a refusal that says how many records were stored. A manifest without `counts` is a refusal, not a `KeyError`. The manifest is written atomically and an import that fails part-way closes its open part.

#### Changed
- OpenAlex imports now contain author nodes, so node counts for the same dump are higher than before.
- `stage_library` and `stage_scores` receive and return `ledger_total`.
- The documented order of license strictness was wrong in SPEC.md (it put PERMISSIVE above NON_COMMERCIAL_OR_RESTRICTED); the code's order, now documented, is NON_COMMERCIAL_OR_RESTRICTED, STRONG_COPYLEFT, WEAK_COPYLEFT, NO_LICENSE_FILE, PERMISSIVE.

#### Not changed
- Scores are structure measurements, not tests of the code. The vet is a static read, not proof of safety.
