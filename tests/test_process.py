"""The whole 'process this repo' workflow on a tiny archive, with the real graph builder and a stand-in DKG loader that counts the nodes it was given."""
import json
import os
import pathlib
import tempfile
import unittest
import zipfile

from vega_dkg import process

MIT = "MIT License\n\nPermission is hereby granted, free of charge, to any person obtaining a copy of this software.\n"
APP = '''"""app"""
import json


def fetch(url, retries):
    total = 0
    for i in range(retries):
        data = get(url)
        total = total + len(data)
    return total


def safe(url):
    try:
        return fetch(url, 3)
    except Exception:
        return None
'''
TEST = "from pkg.app import fetch\n\n\ndef test_fetch():\n    assert fetch\n"
LOADER = '''import json, sys
g = json.load(open(sys.argv[1], encoding="utf-8"))
tag = sys.argv[sys.argv.index("--tag") + 1]
print("in Neo4j database %r: GNode[%s]=%s  LINK=1  Hyperedge=0" % (sys.argv[2], tag, "{:,}".format(len(g["nodes"]))))
'''
BAD_LOADER = LOADER.replace('len(g["nodes"])', 'len(g["nodes"]) + 1')


def make_zip(path, files, top="tiny-main"):
    with zipfile.ZipFile(path, "w") as z:
        for name, text in files.items():
            z.writestr(f"{top}/{name}", text)


def fixture(loader=LOADER, files=None, load_dkg=True):
    t = pathlib.Path(tempfile.mkdtemp())
    for d in ("vet", "lib", "md", "plane", "dag"):
        (t / d).mkdir()
    (t / "matrix.json").write_text("[]", encoding="utf-8")
    (t / "loader.py").write_text(loader, encoding="utf-8")
    files = files if files is not None else {"LICENSE": MIT, "README.md": "# tiny\n", "pkg/app.py": APP, "tests/test_app.py": TEST, ".env": "TOKEN=nothing-to-see\n"}
    make_zip(t / "tiny-main.zip", files)
    cfg = process.Config(t / "vet", t / "lib", t / "md", t / "plane", t / "matrix.json", t / "dag", loader=str(t / "loader.py"), load_dkg=load_dkg, timeout=300)
    return t, cfg


class Workflow(unittest.TestCase):
    def test_every_stage_runs_and_the_report_says_complete(self):
        t, cfg = fixture()
        rep = process.process(str(t / "tiny-main.zip"), cfg)
        self.assertTrue(rep["complete"], json.dumps(rep["stages"], indent=1)[:1500])
        self.assertEqual([s for s in process.STAGES if not rep["stages"][s]["ok"]], [])
        lib = t / "lib" / "tiny-main"
        for f in ("INGEST_MANIFEST.csv", "verify.json", "score.json", "score_card.md", "variables.jsonl", "PROCESS_REPORT.md", "graphify-out/graph.json"):
            self.assertTrue((lib / f).exists(), f)
        self.assertIn("COMPLETE", (lib / "PROCESS_REPORT.md").read_text(encoding="utf-8"))
        self.assertEqual(json.loads((t / "matrix.json").read_text(encoding="utf-8"))[0]["license_class"], "PERMISSIVE")

    def test_every_variable_is_a_scored_row(self):
        t, cfg = fixture()
        process.process(str(t / "tiny-main.zip"), cfg)
        rows = [json.loads(x) for x in (t / "lib" / "tiny-main" / "variables.jsonl").read_text(encoding="utf-8").splitlines()]
        names = {(r["symbol"], r["variable"]) for r in rows}
        self.assertIn(("fetch", "total"), names)
        self.assertIn(("fetch", "data"), names)
        total = next(r for r in rows if (r["symbol"], r["variable"]) == ("fetch", "total"))
        self.assertEqual((total["role"], total["writes"] >= 2, total["reads"] >= 1), ("read_write", True, True))
        self.assertTrue(all(len(r["variable_id"]) == 30 and r["symbol_vega_id"].startswith("vn1_") for r in rows))

    def test_scores_hold_graph_and_variable_measures(self):
        t, cfg = fixture()
        process.process(str(t / "tiny-main.zip"), cfg)
        s = json.loads((t / "lib" / "tiny-main" / "score.json").read_text(encoding="utf-8"))
        self.assertEqual(set(s["dimensions"]), {"provenance_completeness", "documentation_share", "test_share_of_code", "graph_connectedness", "graph_edges_extracted_not_inferred", "graph_edges_internal"})
        self.assertGreater(s["symbol_aggregates"]["variables"], 3)

    def test_the_secret_named_file_is_skipped_and_never_read(self):
        t, cfg = fixture()
        rep = process.process(str(t / "tiny-main.zip"), cfg)
        self.assertEqual(rep["stages"]["vet"]["secret_named_skipped"], [".env"])
        manifest = (t / "lib" / "tiny-main" / "INGEST_MANIFEST.csv").read_text(encoding="utf-8")
        self.assertIn("SKIPPED_SECRET", manifest)

    def test_the_license_is_read_and_a_mixed_repo_takes_the_strictest(self):
        files = {"LICENSE": MIT, "studio/LICENSE": "GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3\n", "pkg/app.py": APP}
        t, cfg = fixture(files=files)
        rep = process.process(str(t / "tiny-main.zip"), cfg)
        self.assertEqual(rep["stages"]["vet"]["license_class"], "STRONG_COPYLEFT")
        self.assertIn("more than one license class", " ".join(rep["stages"]["vet"]["flags"]))

    def test_no_license_file_means_no_permission(self):
        t, cfg = fixture(files={"pkg/app.py": APP})
        rep = process.process(str(t / "tiny-main.zip"), cfg)
        self.assertEqual(rep["stages"]["vet"]["license_class"], "NO_LICENSE_FILE")


class NeverHalfDone(unittest.TestCase):
    def test_a_loader_that_stores_the_wrong_count_means_not_complete_and_says_where(self):
        t, cfg = fixture(loader=BAD_LOADER)
        rep = process.process(str(t / "tiny-main.zip"), cfg)
        self.assertFalse(rep["complete"])
        self.assertEqual(rep["failed_at"], "dkg_load")
        self.assertIn("INCOMPLETE: failed at dkg_load", (t / "lib" / "tiny-main" / "PROCESS_REPORT.md").read_text(encoding="utf-8"))

    def test_with_the_dkg_load_switched_off_the_workflow_is_never_called_complete(self):
        t, cfg = fixture(load_dkg=False)
        rep = process.process(str(t / "tiny-main.zip"), cfg)
        self.assertFalse(rep["complete"])
        self.assertEqual(rep["failed_at"], "dkg_load")
        self.assertTrue(all(rep["stages"][s]["ok"] for s in ("intake", "extract", "vet", "library", "md_nodes", "graph", "cards", "scores")))

    def test_a_failure_skips_everything_after_it_and_records_the_run(self):
        t, cfg = fixture()
        (t / "loader.py").write_text("raise SystemExit(5)", encoding="utf-8")
        rep = process.process(str(t / "tiny-main.zip"), cfg)
        self.assertEqual(rep["failed_at"], "dkg_load")
        self.assertTrue(rep["stages"]["dag"]["ok"])
        from vega_custody.dag.dag import Dag
        d = Dag([t / "dag" / "PROCESS_DAG.jsonl"], [t / "dag" / "PROCESS_DAG_LOC.jsonl"])
        e = d.content.entries()[-1]
        self.assertEqual((e["kind"], e["payload"]["failed_at"], e["payload"]["stages"]["graph"]), ("PROCESS_REPO", "dkg_load", True))

    def test_a_repo_is_processed_once_per_name(self):
        t, cfg = fixture()
        self.assertTrue(process.process(str(t / "tiny-main.zip"), cfg)["complete"])
        again = process.process(str(t / "tiny-main.zip"), cfg)
        self.assertFalse(again["complete"])
        self.assertEqual(again["failed_at"], "extract")


if __name__ == "__main__":
    unittest.main()
