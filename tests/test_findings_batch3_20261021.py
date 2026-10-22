"""Findings from a line-by-line source read, 2026-10-21, batch 3 (process, knowledge_import). Each test failed before its fix."""
import csv
import json
import os
import tempfile
import threading
import unittest

from test_dkg import make_library
from vega_dkg import knowledge_import as ki
from vega_dkg import process

MIT = "MIT License\n\nPermission is hereby granted, free of charge, to any person obtaining a copy\n"
GPL = "GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007\n"


def tree(root, files):
    for rel, text in files.items():
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w", encoding="utf-8", newline="\n").write(text)
    return root


def make_cfg(base, rows=()):
    mp = os.path.join(base, "matrix.json")
    json.dump(list(rows), open(mp, "w", encoding="utf-8"))
    return process.Config(os.path.join(base, "vet"), os.path.join(base, "lib"), os.path.join(base, "md"), os.path.join(base, "plane"), mp, os.path.join(base, "dag"), load_dkg=False)


class A_Vet(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.d.cleanup()

    def test_a_root_license_decides_the_class(self):
        r = tree(os.path.join(self.d.name, "a"), {"LICENSE": MIT, "app.py": "x = 1\n"})
        self.assertEqual(process.stage_vet(r)["license_class"], "PERMISSIVE")

    def test_license_files_only_in_vendored_folders_do_not_license_the_repo(self):
        r = tree(os.path.join(self.d.name, "b"), {"vendor/lib/LICENSE": MIT, "app.py": "x = 1\n"})
        v = process.stage_vet(r)
        self.assertEqual(v["license_class"], "NO_LICENSE_FILE")
        self.assertTrue(any("subfolder" in f for f in v["flags"]), v["flags"])

    def test_a_stricter_vendored_license_still_raises_the_class(self):
        r = tree(os.path.join(self.d.name, "c"), {"LICENSE": MIT, "vendor/x/COPYING": GPL})
        self.assertEqual(process.stage_vet(r)["license_class"], "STRONG_COPYLEFT")

    def test_a_source_file_named_like_a_license_is_not_a_license_file(self):
        r = tree(os.path.join(self.d.name, "d"), {"LICENSE": MIT, "src/license_utils.py": '"""See the GNU GENERAL PUBLIC LICENSE for details."""\n'})
        v = process.stage_vet(r)
        self.assertEqual(v["license_class"], "PERMISSIVE")
        self.assertEqual([x["file"] for x in v["license_files"]], ["LICENSE"])


class B_Library(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.cfg = make_cfg(self.d.name)

    def tearDown(self):
        self.d.cleanup()

    def test_secret_named_files_are_not_copied_into_the_library(self):
        root = tree(os.path.join(self.d.name, "src"), {".env": "API_KEY=notarealkey\n", ".env.example": "API_KEY=\n", "app.py": "x = 1\n"})
        vet = process.stage_vet(root)
        lib = process.stage_library("x.zip", self.cfg, "r1", root, vet, {"archive_sha256": "0" * 64, "members": 3}, [], "PERMISSIVE")
        dst = os.path.join(self.cfg.library, "r1", "r1")
        self.assertFalse(os.path.exists(os.path.join(dst, ".env")))
        self.assertTrue(os.path.exists(os.path.join(dst, ".env.example")))
        rows = list(csv.DictReader(open(os.path.join(self.cfg.library, "r1", "INGEST_MANIFEST.csv"), encoding="utf-8", newline="")))
        self.assertEqual(sum(1 for r in rows if r["disposition"] == "SKIPPED_SECRET"), 1)
        self.assertEqual((lib["kept"], lib["ledger_total"]), (2, 3))

    def test_the_provenance_dimension_counts_the_files_that_were_not_kept(self):
        os.makedirs(os.path.join(self.cfg.library, "r1"))
        g = os.path.join(self.d.name, "graph.json")
        json.dump({"nodes": [{"id": "a"}], "links": []}, open(g, "w"))
        lib = {"kept": 2, "code_files": 1, "test_files": 0, "doc_files": 1, "ledger_total": 3}
        md = {"files": 1, "symbols": 0, "not_extracted": 0, "failed": 0, "variables_path": None}
        process.stage_scores(self.cfg, "r1", lib, md, g)
        dims = json.load(open(os.path.join(self.cfg.library, "r1", "score.json")))["dimensions"]
        self.assertEqual((dims["provenance_completeness"]["pos"], dims["provenance_completeness"]["n"]), (2, 3))


class C_Matrix(unittest.TestCase):
    def test_two_runs_adding_rows_at_once_lose_none(self):
        d = tempfile.mkdtemp()
        cfg = make_cfg(d)
        errors = []

        def add(prefix):
            try:
                for i in range(15):
                    process.add_matrix_row(cfg, {"repo": "%s%d" % (prefix, i), "license_class": "PERMISSIVE"})
            except Exception as exc:                             # noqa: BLE001
                errors.append(repr(exc))
        ts = [threading.Thread(target=add, args=(p,)) for p in "ab"]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(errors, [])
        self.assertEqual(len(json.load(open(cfg.matrix_path, encoding="utf-8"))), 30)

    def test_a_repo_already_in_the_matrix_is_refused_even_if_another_run_added_it(self):
        d = tempfile.mkdtemp()
        cfg = make_cfg(d)
        process.add_matrix_row(cfg, {"repo": "r", "license_class": "PERMISSIVE"})
        with self.assertRaises(process.ProcessRefused):
            process.add_matrix_row(cfg, {"repo": "r", "license_class": "PERMISSIVE"})

    def test_a_license_class_override_must_be_a_known_class(self):
        d = tempfile.mkdtemp()
        with self.assertRaises(process.ProcessRefused):
            process.process(os.path.join(d, "x.zip"), make_cfg(d), "r1", "permissive")


class D_Refresh(unittest.TestCase):
    def test_refresh_counts_kept_files_not_manifest_lines(self):
        d = tempfile.mkdtemp()
        lib = os.path.join(d, "lib")
        rd = make_library(lib, extra_rows=["SKIPPED_SECRET,name matches secret pattern,,x"])
        os.makedirs(os.path.join(rd, "graphify-out"))
        json.dump({"nodes": [], "links": []}, open(os.path.join(rd, "graphify-out", "graph.json"), "w"))
        cfg = make_cfg(d, [{"repo": "r1", "license_class": "PERMISSIVE"}])
        seen = {}
        real = process.stage_scores

        def spy(cfg_, name, lib_, md, gp):
            seen.update(lib_)
            return real(cfg_, name, lib_, md, gp)
        process.stage_scores = spy
        try:
            process.refresh("r1", cfg)
        finally:
            process.stage_scores = real
        self.assertEqual(seen["kept"], 2)


class E_Import(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def _write(self, name, lines):
        p = os.path.join(self.d, name)
        open(p, "w", encoding="utf-8", newline="\n").write("".join(json.dumps(x) + "\n" if not isinstance(x, str) else x for x in lines))
        return p

    def test_a_deeply_nested_line_is_counted_as_bad_not_fatal(self):
        p = self._write("deep.jsonl", ["[" * 100000 + "]" * 100000 + "\n", {"id": "Q1", "type": "item"}])
        stats = {}
        got = list(ki.iter_json_lines(p, stats))
        self.assertEqual((len(got), stats.get("bad_json")), (1, 1))

    def test_odd_wikidata_shapes_are_skipped_and_counted(self):
        for ent in ({"id": "Q1", "type": "item", "claims": [1, 2]}, {"id": "Q1", "type": "item", "labels": ["x"]}, {"id": "Q1", "type": "item", "claims": {"P31": 5}},
                    {"id": "Q1", "type": "item", "descriptions": 3}):
            stats = {}
            self.assertEqual(ki.wikidata_records(ent, ki.Filter(), stats), ([], [], []), ent)
            self.assertEqual(stats.get("skipped_shape"), 1)

    def test_a_references_field_that_is_text_makes_no_edges(self):
        nodes, edges, refs = ki.openalex_records({"id": "https://openalex.org/W1", "title": "t", "referenced_works": "https://openalex.org/W9"}, ki.Filter(), {})
        self.assertEqual((len(edges), refs), (0, []))

    def test_openalex_authorship_edges_do_not_dangle(self):
        p = self._write("oa.jsonl", [{"id": "https://openalex.org/W1", "title": "t", "authorships": [{"author": {"id": "https://openalex.org/A1", "display_name": "N"}}]}])
        out = os.path.join(self.d, "oa_out")
        m = ki.import_dump(p, "openalex", out)
        ids, ends = set(), []
        for part in m["parts"]:
            for line in open(os.path.join(out, part["file"]), encoding="utf-8"):
                r = json.loads(line)
                if r["kind"] == "edge":
                    ends += [r["src"], r["dst"]]
                else:
                    ids.add(r["vega_id"])
        self.assertEqual([e for e in ends if e not in ids], [])

    def test_a_second_import_into_the_same_folder_is_refused_and_the_first_manifest_stands(self):
        p = self._write("wd.jsonl", [{"id": "Q1", "type": "item", "labels": {"en": {"value": "a"}}}])
        out = os.path.join(self.d, "out")
        ki.import_dump(p, "wikidata", out)
        before = open(os.path.join(out, "wikidata-MANIFEST.json"), encoding="utf-8").read()
        with self.assertRaises(ki.ImportRefused):
            ki.import_dump(p, "wikidata", out)
        self.assertEqual(open(os.path.join(out, "wikidata-MANIFEST.json"), encoding="utf-8").read(), before)

    def test_a_record_bigger_than_the_part_limit_is_not_written_into_a_part(self):
        w = ki.PartWriter(os.path.join(self.d, "tiny"), "wikidata", 1024)
        self.assertFalse(w.write({"kind": "x", "pad": "y" * 3000}))
        self.assertTrue(w.write({"kind": "x", "pad": "y"}))
        self.assertTrue(all(p["bytes"] <= 1024 for p in w.finish()))

    def test_the_id_limit_counts_edge_targets_too(self):
        claims = {"P%d" % i: [{"mainsnak": {"snaktype": "value", "datavalue": {"type": "wikibase-entityid", "value": {"id": "Q%d" % (100 + i)}}}}] for i in range(10)}
        p = self._write("wd2.jsonl", [{"id": "Q1", "type": "item", "claims": claims}])
        with self.assertRaises(ki.ImportRefused):
            ki.import_dump(p, "wikidata", os.path.join(self.d, "out2"), max_ids=5)

    def _batch(self):
        p = self._write("wd3.jsonl", [{"id": "Q1", "type": "item", "labels": {"en": {"value": "a"}}}])
        out = os.path.join(self.d, "out3")
        return ki.import_dump(p, "wikidata", out), out

    def test_a_loader_that_fails_is_reported_as_a_refusal_with_the_count_so_far(self):
        m, out = self._batch()

        def bad(batch):
            raise RuntimeError("database went away")
        with self.assertRaises(ki.ImportRefused) as cm:
            ki.load(m, out, bad, lambda a, p: True)
        self.assertIn("loader failed", str(cm.exception))

    def test_a_manifest_without_counts_is_a_refusal_not_a_key_error(self):
        m, out = self._batch()
        m2 = {k: v for k, v in m.items() if k != "counts"}
        with self.assertRaises(ki.ImportRefused):
            ki.load(m2, out, lambda b: len(b), lambda a, p: True)


if __name__ == "__main__":
    unittest.main()
