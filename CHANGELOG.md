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
