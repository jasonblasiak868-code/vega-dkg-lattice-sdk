"""Functional tests: crosswalk ids, md code nodes, repo cards, combine finder, candidate verification, and the round trip between them."""
import json
import os
import tempfile
import unittest

from vega_dkg import candidate_verify as cv
from vega_dkg import cards
from vega_dkg import combine_finder as cf
from vega_dkg import md_nodes
from vega_dkg import vega_id as v


def row(i, label="f", loc="L1", path="a/b.py", uni="repo1", kind="function"):
    return dict(local_id=i, universe=uni, path=path, kind=kind, label=label, location=loc)


class Ids(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.cw = v.Crosswalk(os.path.join(self.d.name, "cw.db"))

    def tearDown(self):
        self.cw.close()
        self.d.cleanup()

    def test_same_logical_node_gets_same_id_in_two_layers(self):
        self.cw.add_many("supergraph", [row("sg-1")])
        self.cw.add_many("codegraphs", [row("cg-9", path="A\\B.py", label=" F ", uni="REPO1")])
        self.assertEqual(self.cw.lookup("supergraph", "sg-1"), self.cw.lookup("codegraphs", "cg-9"))

    def test_duplicates_are_separate_ids_and_flagged_not_merged(self):
        self.cw.add_many("L", [row("z"), row("a"), row("m")])
        self.assertEqual(len({self.cw.lookup("L", k) for k in "azm"}), 3)
        s = self.cw.stats()[0]
        self.assertEqual((s["nodes"], s["in_collision_groups"], s["distinct_vega_ids"]), (3, 3, 3))

    def test_deterministic_regardless_of_input_order(self):
        self.cw.add_many("L1", [row("x"), row("y")])
        with v.Crosswalk(os.path.join(self.d.name, "cw2.db")) as d2:
            d2.add_many("L1", [row("y"), row("x")])
            self.assertEqual(self.cw.lookup("L1", "x"), d2.lookup("L1", "x"))

    def test_write_once(self):
        self.cw.add_many("L", [row("k", label="one")])
        first = self.cw.lookup("L", "k")
        self.cw.add_many("L", [row("k", label="different")])
        self.assertEqual(self.cw.lookup("L", "k"), first)

    def test_local_id_stored_whole_even_when_long(self):
        long_id = "q" * 5000
        self.cw.add_many("L", [row(long_id)])
        self.assertIsNotNone(self.cw.lookup("L", long_id))


PY_SRC = '''def fetch(url):
    """Fetch."""
    a = get(url)
    b = parse(a)
    c = save(b)
    log(c)
    return c


def safe_fetch(url):
    try:
        return get(url)
    except Exception:
        return retry(url)
'''
TEST_SRC = "from a import fetch\n\ndef test_fetch():\n    assert fetch('x')\n"


def make_library(lib, repo="r1", files=None, extra_rows=()):
    files = files or {"a.py": PY_SRC, "test_a.py": TEST_SRC}
    rd = os.path.join(lib, repo)
    os.makedirs(rd, exist_ok=True)
    rows = ["disposition,detail,sha256,source_path"]
    for name, text in files.items():
        with open(os.path.join(rd, name), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        rows.append("KEPT,%s,abc,%s" % (name, name))
    rows += list(extra_rows)
    with open(os.path.join(rd, "INGEST_MANIFEST.csv"), "w", encoding="utf-8", newline="") as fh:
        fh.write("\n".join(rows) + "\n")
    return rd


class Builders(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.lib, self.out = os.path.join(self.d.name, "lib"), os.path.join(self.d.name, "out")
        self.matrix = {"r1": {"repo": "r1", "license_class": "PERMISSIVE", "personal_build": "ok", "public_build": "clean-room only", "taint_if_used": True}}

    def tearDown(self):
        self.d.cleanup()

    def test_md_nodes_round_trip_into_the_combine_finder(self):
        make_library(self.lib)
        stats = md_nodes.build_repo("r1", self.lib, self.out, self.matrix)
        self.assertEqual((stats["files"], stats["failed"], stats["symbols"]), (2, 0, 3))
        nodes, report = cf.load(["r1"], self.out)
        self.assertEqual((len(nodes), report["skipped_malformed"]), (2, 0))
        names = {s["name"] for n in nodes for s in n["syms"]}
        self.assertEqual(names, {"fetch", "safe_fetch", "test_fetch"})
        props = cf.propose(nodes)
        self.assertTrue(props)
        fix = [q for q in props if q["fixes"] == "no error handling"][0]
        self.assertEqual((fix["weak_symbol"]["name"], fix["strong_symbol"]["name"], fix["strictest_license_class"]), ("fetch", "safe_fetch", "PERMISSIVE"))

    def test_md_nodes_hold_no_source_text(self):
        make_library(self.lib)
        md_nodes.build_repo("r1", self.lib, self.out, self.matrix)
        text = open(os.path.join(self.out, "r1", "a.py.md"), encoding="utf-8").read()
        self.assertNotIn("Fetch.", text)
        self.assertNotIn("return retry(url)", text)

    def test_cards_build_for_a_repo_with_a_graph(self):
        rd = make_library(self.lib)
        os.makedirs(os.path.join(rd, "graphify-out"))
        graph = {"nodes": [{"id": "n1", "label": "fetch", "source_file": "a.py", "source_location": "L1", "file_type": "code"}],
                 "links": [{"source": "n1", "target": "n1", "confidence": "EXTRACTED"}]}
        json.dump(graph, open(os.path.join(rd, "graphify-out", "graph.json"), "w", encoding="utf-8"))
        with v.Crosswalk(os.path.join(self.d.name, "cw.db")) as cw:
            cov = cards.build("r1", self.lib, self.out, cw, self.matrix, {})
        self.assertEqual((cov["files_kept"], cov["files_with_nodes"], cov["code_nodes"], cov["nodes_without_vega_id"]), (2, 1, 1, 0))
        lines = open(os.path.join(self.out, "cards", "r1.jsonl"), encoding="utf-8").read().splitlines()
        self.assertEqual(json.loads(lines[0])["kind"], "repo_node")
        self.assertEqual(cv.verify_node("r1", 3, os.path.join(self.out, "cards"))["license_class"], "PERMISSIVE")


class Finder(unittest.TestCase):
    def test_no_overlap_no_pair_and_license_is_strictest_and_always_tainted(self):
        def sym(name, weak, strong, calls):
            return {"vega_id": "vn1_" + name, "name": name, "kind": "function", "lines": 20, "weak": weak, "strong": strong, "calls": set(calls), "fan_in": 0, "tested": False}

        def node(repo, lic, s):
            return {"path": s["name"] + ".py", "repo": repo, "language": "python", "license_class": lic, "syms": [s]}
        a = node("a", "PERMISSIVE", sym("f", "no error handling (3 calls)", "documented", ["x1", "x2", "x3"]))
        b = node("b", "STRONG_COPYLEFT", sym("g", "undocumented", "handles errors", ["y1", "y2"]))
        self.assertEqual(cf.propose([a, b]), [])
        c = node("c", "STRONG_COPYLEFT", sym("h", "undocumented", "handles errors", ["x1", "x2"]))
        p = cf.propose([a, c])[0]
        self.assertEqual((p["strictest_license_class"], p["tainted_if_used"]), ("STRONG_COPYLEFT", True))
        self.assertIn("contained run in the evaluation sandbox", p["needs"])


def card(d, repo, lic="PERMISSIVE", status="COMPLETE", tests=0.3, extracted=0.9):
    with open(os.path.join(d, repo + ".jsonl"), "w", encoding="utf-8") as f:
        f.write(json.dumps({"kind": "repo_node", "repo": repo, "license_class": lic, "audit_status": status,
                            "score_dimensions": {"test_share_of_code": tests, "graph_edges_extracted_not_inferred": extracted}}) + "\n")


class Verify(unittest.TestCase):
    def setUp(self):
        cv._cache.clear()
        self.d = tempfile.mkdtemp()

    def test_all_five_pass(self):
        card(self.d, "good")
        r = cv.verify_node("good", 5, self.d)
        self.assertTrue(r["passes"])
        self.assertGreaterEqual(r["score"], 1.0)

    def test_each_failure_is_named_and_unknown_degree_does_not_pass(self):
        card(self.d, "bad", lic="STRONG_COPYLEFT", tests=0.0)
        r = cv.verify_node("bad", 1, self.d)
        self.assertFalse(r["passes"])
        for k in ("c1_permissive", "c3_test_evidence", "c4_connected"):
            self.assertIn(k, r["why"])
        card(self.d, "ok2")
        self.assertFalse(cv.verify_node("ok2", None, self.d)["passes"])

    def test_missing_card_verifies_nothing(self):
        r = cv.verify_candidate({"repo": "nope"}, self.d)
        self.assertFalse(r["passes"])
        self.assertIn("nothing verified", r["why"])

    def test_combination_is_never_passed_and_weaker_parent_decides(self):
        card(self.d, "a")
        card(self.d, "b", lic="NO_LICENSE_FILE", tests=0.0)
        r = cv.verify_candidate({"weak_symbol": {"repo": "a"}, "strong_symbol": {"repo": "b"}}, self.d)
        self.assertFalse(r["passes"])
        self.assertEqual(r["score"], cv.verify_node("b", None, self.d)["score"])
        self.assertIn("hypothesis", r["why"])

    def test_locked_workflow_is_not_graph_verifiable(self):
        self.assertFalse(cv.verify_candidate({"kind": "locked_workflow", "workflow": "x"}, self.d)["passes"])


if __name__ == "__main__":
    unittest.main()
