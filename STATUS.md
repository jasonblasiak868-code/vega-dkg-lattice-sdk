# STATUS 

## BUILT and tested

- vega_id
- cards
- md_nodes
- combine_finder
- candidate_verify
- safe_paths
- knowledge_import

Tests: 133 tests in 9 files, all passing. Every fix in `tests/mutations.py` was checked by undoing it and confirming a test fails (see CHANGELOG.md).

## DESIGNED ONLY (not built)

- Wikipedia article text (share-alike, so tainted) and any other source need their own adapter; WikiLeaks is deliberately not a source.
- Kinetic energy and scorer outputs on cards are not_scored placeholders.
- Multi-language symbol extraction needs tree-sitter-language-pack, which is not installed by default.

## Release

Source-available under the LICENSE in this folder. Patent pending (U.S. provisional application 64/178,949 and others). The licence text is a draft that has not been reviewed by an attorney.
