"""Findings from a line-by-line source read, 2026-10-21, batch 1 (vega_id, candidate_verify, cards). Each test failed before its fix."""
import json
import os
import tempfile
import threading
import unittest

from test_dkg import make_library, row
from vega_dkg import candidate_verify as cv
from vega_dkg import cards
from vega_dkg import vega_id as v


class A_Crosswalk(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.d.name, "cw.db")

    def tearDown(self):
        self.d.cleanup()

    def test_the_same_local_id_twice_in_one_batch_does_not_abort_the_batch(self):
        with v.Crosswalk(self.path) as cw:
            rep = cw.add_many("L", [row("k"), row("k"), row("other", label="g")])
            self.assertEqual((rep["added"], rep["unchanged"], rep["conflicts"]), (2, 1, []))
            self.assertIsNotNone(cw.lookup("L", "k"))
            self.assertIsNotNone(cw.lookup("L", "other"))

    def test_the_same_local_id_with_different_content_is_reported_and_the_first_is_kept(self):
        with v.Crosswalk(self.path) as cw:
            rep = cw.add_many("L", [row("k", label="one"), row("k", label="two")])
            self.assertEqual((rep["added"], len(rep["conflicts"])), (1, 1))
            self.assertEqual(rep["conflicts"][0]["local_id"], "k")
            with v.Crosswalk(os.path.join(self.d.name, "ref.db")) as ref:
                ref.add_many("L", [row("k", label="one")])
                self.assertEqual(cw.lookup("L", "k"), ref.lookup("L", "k"))

    def test_two_writers_adding_the_same_node_at_once_both_succeed_with_different_ids(self):
        gate = threading.Barrier(2)
        real = v._base_key

        def slow(tup):
            try:
                gate.wait(timeout=1.5)               # make both writers finish reading before either writes
            except threading.BrokenBarrierError:
                pass
            return real(tup)
        v._base_key = slow
        errors, results = [], []

        def writer(local_id):
            try:
                with v.Crosswalk(self.path) as cw:
                    results.append(cw.add_many("L", [row(local_id)]))
            except Exception as exc:                 # noqa: BLE001 - the test wants to see any failure
                errors.append(repr(exc))
        try:
            ts = [threading.Thread(target=writer, args=(n,)) for n in ("a", "b")]
            [t.start() for t in ts]
            [t.join() for t in ts]
        finally:
            v._base_key = real
        self.assertEqual(errors, [])
        with v.Crosswalk(self.path) as cw:
            self.assertNotEqual(cw.lookup("L", "a"), cw.lookup("L", "b"))
            self.assertEqual(cw.stats()[0]["distinct_vega_ids"], 2)


class B_CandidateCache(unittest.TestCase):
    def test_the_card_cache_is_bounded(self):
        d = tempfile.mkdtemp()
        old = cv.MAX_CACHE
        cv.MAX_CACHE = 8
        cv._cache.clear()
        try:
            for i in range(20):
                with open(os.path.join(d, "r%d.jsonl" % i), "w", encoding="utf-8") as fh:
                    fh.write(json.dumps({"kind": "repo_node", "repo": "r%d" % i, "license_class": "PERMISSIVE"}) + "\n")
            for i in range(20):
                self.assertEqual(cv.repo_facts("r%d" % i, d)["repo"], "r%d" % i)
            self.assertLessEqual(len(cv._cache), 8)
        finally:
            cv.MAX_CACHE = old
            cv._cache.clear()


class C_Cards(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.lib, self.out = os.path.join(self.d.name, "lib"), os.path.join(self.d.name, "out")

    def tearDown(self):
        self.d.cleanup()

    def _graph(self, rd, nodes, links=()):
        os.makedirs(os.path.join(rd, "graphify-out"), exist_ok=True)
        json.dump({"nodes": nodes, "links": list(links)}, open(os.path.join(rd, "graphify-out", "graph.json"), "w", encoding="utf-8"))

    def test_fields_the_matrix_does_not_have_are_not_scored(self):
        make_library(self.lib)
        with v.Crosswalk(os.path.join(self.d.name, "cw.db")) as cw:
            cards.build("r1", self.lib, self.out, cw, {}, {})
        first = json.loads(open(os.path.join(self.out, "cards", "r1.jsonl"), encoding="utf-8").readline())
        for k in ("personal_build", "public_build", "audit_policy", "archive_sha256", "audit_status"):
            self.assertEqual(first[k], "not_scored", k)
        self.assertEqual(first["license_class"], "UNKNOWN")
        self.assertIs(first["taint_if_used"], True)

    def test_a_graph_that_repeats_a_node_id_does_not_abort_the_repo(self):
        rd = make_library(self.lib)
        node = {"id": "n1", "label": "fetch", "source_file": "a.py", "source_location": "L1", "file_type": "code"}
        self._graph(rd, [node, dict(node), {"id": "n2", "label": "g", "source_file": "a.py", "source_location": "L9", "file_type": "code"}])
        with v.Crosswalk(os.path.join(self.d.name, "cw.db")) as cw:
            cov = cards.build("r1", self.lib, self.out, cw, {"r1": {"repo": "r1", "license_class": "PERMISSIVE"}}, {})
        self.assertEqual(cov["nodes_without_vega_id"], 0)

    def test_a_path_in_another_folder_does_not_borrow_a_top_level_files_nodes(self):
        rd = make_library(self.lib, extra_rows=["KEPT,src/a.py,abc,src/a.py"])
        self._graph(rd, [{"id": "n1", "label": "fetch", "source_file": "a.py", "source_location": "L1", "file_type": "code"}])
        with v.Crosswalk(os.path.join(self.d.name, "cw.db")) as cw:
            cov = cards.build("r1", self.lib, self.out, cw, {"r1": {"repo": "r1", "license_class": "PERMISSIVE"}}, {})
        self.assertEqual(cov["files_with_nodes"], 1)                 # a.py only
        self.assertIn("src/a.py", cov["files_without_nodes"])

    def test_an_archive_top_folder_is_still_stripped_when_every_path_shares_it(self):
        rd = os.path.join(self.lib, "r1")
        os.makedirs(rd)
        open(os.path.join(rd, "INGEST_MANIFEST.csv"), "w", encoding="utf-8").write(
            "disposition,detail,sha256,source_path\nKEPT,r1-main/a.py,abc,x\nKEPT,r1-main/src/c.py,abc,y\nKEPT,r1-main/none.py,abc,z\n")
        self._graph(rd, [{"id": "n1", "label": "f", "source_file": "a.py", "source_location": "L1", "file_type": "code"},
                         {"id": "n2", "label": "g", "source_file": "src/c.py", "source_location": "L1", "file_type": "code"}])
        with v.Crosswalk(os.path.join(self.d.name, "cw.db")) as cw:
            cov = cards.build("r1", self.lib, self.out, cw, {"r1": {"repo": "r1", "license_class": "PERMISSIVE"}}, {})
        self.assertEqual((cov["files_kept"], cov["files_with_nodes"]), (3, 2))


if __name__ == "__main__":
    unittest.main()
