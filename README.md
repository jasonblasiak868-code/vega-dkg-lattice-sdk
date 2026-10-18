# vega-dkg-lattice-sdk

![vega-dkg-lattice-sdk](assets/tile.svg)

DKG lattice: one node id across layers, repo and doc cards, markdown code nodes, combination hypotheses and graph-fact verification.

> **Licensing.** Source-available, not open source. Free for personal use; free for registered small businesses (under US$1M revenue and valuation); everyone else needs a commercial license (see LICENSE; for a commercial license write to jasonblasiak.ai.mail@gmail.com). Patent pending. Draft licence text, not yet reviewed by an attorney.

Package: `vega_dkg` (src layout). Depends on: vega-harness-sdk.

## Modules

| Module | What it does |
|---|---|
| `vega_id` | One id for a node in every layer, with a crosswalk that reports changed rows instead of ignoring them and never gives two nodes one id. |
| `cards` | Repo, code and doc cards for a library, built read-only with safe paths and atomic writes. |
| `md_nodes` | One markdown code node per source file with measured per-symbol scores and no source text. Python precisely; other languages need the optional tree-sitter extra. |
| `combine_finder` | Pairs a weak symbol with a strong one as a HYPOTHESIS card; indexed, bounded, tainted by default. |
| `candidate_verify` | Checks a candidate against card facts without running anything; a combination never passes on its own. |
| `safe_paths` | Plain-name, containment, size-cap and atomic-write rules for untrusted repos. |
| `knowledge_import` | Grow the graph from open public knowledge (Wikidata, OpenAlex, arXiv metadata; all CC0) offline: read a downloaded dump line by line, filter, write hashed parts under the size limit with a manifest and one batch hash, load only under one human commitment for that exact batch, and count back what was stored. |

## What it does NOT do (read this)

- A score is a measurement of structure, not a prediction that code works.
- A passing graph check is not a test of the code.
- Hypothesis cards are ideas ranked, not merges that were tried.

## Status

See STATUS.md. Tests: 96 tests in 6 files, all passing.  See SECURITY.md for the threat model.

## Run the tests

Put `src` of this repo and of the repos it depends on on PYTHONPATH, then run each file in `tests/`.
