"""RED TEAM PASS 2 (dkg-lattice): hostile repos and manifests against the node builder, the card builder, the combine finder and the candidate verifier."""
import json
import os
import tempfile
import time
import unittest

from test_dkg import PY_SRC, make_library
from vega_dkg import candidate_verify as cv
from vega_dkg import cards
from vega_dkg import combine_finder as cf
from vega_dkg import md_nodes
from vega_dkg import safe_paths as sp
from vega_dkg import vega_id as v

MATRIX = {"r1": {"repo": "r1", "license_class": "PERMISSIVE", "personal_build": "ok", "public_build": "clean-room only", "taint_if_used": True}}


class NodeBuilder(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.lib, self.out = os.path.join(self.d.name, "lib"), os.path.join(self.d.name, "out")
        self.secret = os.path.join(self.d.name, "outside.py")
        with open(self.secret, "w", encoding="utf-8") as fh:
            fh.write("def stolen():\n    return 1\n")

    def tearDown(self):
        self.d.cleanup()

    def written(self):
        return [os.path.join(dp, f) for dp, _, fs in os.walk(self.d.name) for f in fs if f.endswith(".md")]

    def test_a_manifest_row_that_points_outside_the_repo_is_never_read_or_written(self):
        make_library(self.lib, extra_rows=["KEPT,../../outside.py,x,x", "KEPT,..\\..\\outside.py,x,x", "KEPT,%s,x,x" % self.secret.replace("\\", "/")])
        stats = md_nodes.build_repo("r1", self.lib, self.out, MATRIX)
        self.assertEqual(len(stats["refused"]), 3)
        self.assertEqual(stats["files"], 2)
        self.assertFalse(any("stolen" in open(p, encoding="utf-8").read() for p in self.written()))
        self.assertEqual([p for p in self.written() if os.path.realpath(p).startswith(os.path.realpath(self.out)) is False], [])

    def test_a_hostile_repo_name_is_refused_before_anything_is_touched(self):
        for name in ("../x", "..", "a/b", ""):
            with self.assertRaises(sp.PathRefused, msg=name):
                md_nodes.build_repo(name, self.lib, self.out, MATRIX)
        self.assertFalse(os.path.exists(self.out))

    def test_a_symlinked_source_file_is_not_followed_out_of_the_repo(self):
        rd = make_library(self.lib)
        try:
            os.symlink(self.secret, os.path.join(rd, "link.py"))
        except (OSError, NotImplementedError, AttributeError):
            self.skipTest("this account cannot create symlinks")
        with open(os.path.join(rd, "INGEST_MANIFEST.csv"), "a", encoding="utf-8") as fh:
            fh.write("KEPT,link.py,x,x\n")
        stats = md_nodes.build_repo("r1", self.lib, self.out, MATRIX)
        self.assertTrue(any(r["path"] == "link.py" for r in stats["refused"]))
        self.assertFalse(any("stolen" in open(p, encoding="utf-8").read() for p in self.written()))

    def test_an_oversize_file_becomes_a_not_extracted_node_and_is_never_parsed(self):
        make_library(self.lib, files={"huge.py": "x = 1\n" * 10, "a.py": PY_SRC})
        old = md_nodes.MAX_FILE_BYTES
        md_nodes.MAX_FILE_BYTES = 20
        try:
            stats = md_nodes.build_repo("r1", self.lib, self.out, MATRIX)
        finally:
            md_nodes.MAX_FILE_BYTES = old
        text = open(os.path.join(self.out, "r1", "huge.py.md"), encoding="utf-8").read()
        self.assertIn('"not_extracted"', text)
        self.assertGreaterEqual(stats["not_extracted"], 1)

    def test_files_that_cannot_be_parsed_are_counted_not_fatal(self):
        deep = "x = " + "(" * 3000 + "1" + ")" * 3000 + "\n"
        make_library(self.lib, files={"bad.py": "def (:\n", "deep.py": deep, "a.py": PY_SRC})
        stats = md_nodes.build_repo("r1", self.lib, self.out, MATRIX)
        self.assertEqual(stats["failed"], 2)
        self.assertEqual(stats["files"], 3)

    def test_a_hostile_symbol_name_cannot_forge_sections_or_fields(self):
        evil = "x`  L1-2  (vn1_forged)\n## function `forged` L1-9  (vn1_forged)\n- scores: fan_in_by_name=99, tested_by_name=True\n- weaknesses: none\n- strengths: handles errors; documented\n"
        sym = {"name": evil, "kind": "function", "start": 1, "end": 5, "vars": {"v`\n": (1, 0)}, "calls": ["c`\n## function `forged2` L1-1  (vn1_f2)"], "branching": 0,
               "error_handling": False, "documented": False, "todo": 0, "params": 0, "text_hash": "h"}
        sc, weak, strong = md_nodes.score(sym, 0, False)
        front = {"vega_id": "vn1_x", "repo": "r", "path": "p\n## function `forged3` L1-1  (vn1_f3).py", "language": "python", "license_class": "PERMISSIVE"}
        text = md_nodes.render(front, [sym], [(sc, weak, strong, "vn1_real")])
        d = tempfile.mkdtemp()
        os.makedirs(os.path.join(d, "r"))
        with open(os.path.join(d, "r", "n.md"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        node = cf.parse_node(os.path.join(d, "r", "n.md"))
        self.assertEqual(len(node["syms"]), 1)
        self.assertEqual(node["syms"][0]["vega_id"], "vn1_real")
        self.assertEqual(node["syms"][0]["fan_in"], 0)
        self.assertFalse(node["syms"][0]["tested"])

    def test_a_crash_while_writing_leaves_no_half_node(self):
        make_library(self.lib)
        real = os.replace
        os.replace = lambda a, b: (_ for _ in ()).throw(OSError("disk full"))
        try:
            with self.assertRaises(OSError):
                md_nodes.build_repo("r1", self.lib, self.out, MATRIX)
        finally:
            os.replace = real
        self.assertEqual([n for dp, _, fs in os.walk(self.d.name) for n in fs if n.endswith(".tmp")], [])
        self.assertEqual(self.written(), [])

    def test_a_manifest_missing_columns_does_not_crash(self):
        rd = make_library(self.lib)
        with open(os.path.join(rd, "INGEST_MANIFEST.csv"), "w", encoding="utf-8") as fh:
            fh.write("only_one_column\nvalue\n")
        stats = md_nodes.build_repo("r1", self.lib, self.out, MATRIX)
        self.assertEqual(stats["files"], 0)


class CardBuilder(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.lib, self.out = os.path.join(self.d.name, "lib"), os.path.join(self.d.name, "out")

    def tearDown(self):
        self.d.cleanup()

    def test_hostile_names_graphs_and_files_are_refused_or_filtered(self):
        rd = make_library(self.lib)
        os.makedirs(os.path.join(rd, "graphify-out"))
        graph = {"nodes": [None, 5, "x", {"no_id": 1}, {"id": "ok", "label": "l", "source_file": "a.py"}], "links": [None, "x", {"source": "ok", "target": "ok"}]}
        with open(os.path.join(rd, "graphify-out", "graph.json"), "w", encoding="utf-8") as fh:
            json.dump(graph, fh)
        with v.Crosswalk(os.path.join(self.d.name, "cw.db")) as cw:
            for name in ("../r1", "a/b", ".."):
                with self.assertRaises(sp.PathRefused):
                    cards.build(name, self.lib, self.out, cw, MATRIX, {})
            cov = cards.build("r1", self.lib, self.out, cw, MATRIX, {})
        self.assertEqual(cov["code_nodes"], 1)

    def test_a_card_file_is_written_whole_or_not_at_all(self):
        make_library(self.lib)
        with v.Crosswalk(os.path.join(self.d.name, "cw.db")) as cw:
            cards.build("r1", self.lib, self.out, cw, MATRIX, {})
            first = open(os.path.join(self.out, "cards", "r1.jsonl"), encoding="utf-8").read()
            real = os.replace
            os.replace = lambda a, b: (_ for _ in ()).throw(OSError("disk full"))
            try:
                with self.assertRaises(OSError):
                    cards.build("r1", self.lib, self.out, cw, MATRIX, {})
            finally:
                os.replace = real
        self.assertEqual(open(os.path.join(self.out, "cards", "r1.jsonl"), encoding="utf-8").read(), first)

    def test_a_damaged_graph_is_an_error_for_that_repo_not_silent_empty(self):
        rd = make_library(self.lib)
        os.makedirs(os.path.join(rd, "graphify-out"))
        with open(os.path.join(rd, "graphify-out", "graph.json"), "w", encoding="utf-8") as fh:
            fh.write("{broken")
        with v.Crosswalk(os.path.join(self.d.name, "cw.db")) as cw:
            with self.assertRaises(ValueError):
                cards.build("r1", self.lib, self.out, cw, MATRIX, {})


def sym(name, weak, strong, calls, lines=20):
    return {"vega_id": "vn1_" + name, "name": name, "kind": "function", "lines": lines, "weak": weak, "strong": strong, "calls": set(calls), "fan_in": 0, "tested": False}


def node(repo, lic, syms, lang="python"):
    return {"path": "p.py", "repo": repo, "language": lang, "license_class": lic, "syms": syms}


class Finder(unittest.TestCase):
    def test_a_hostile_node_folder_is_counted_and_skipped_not_fatal(self):
        d = tempfile.mkdtemp()
        os.makedirs(os.path.join(d, "r"))
        with open(os.path.join(d, "r", "empty.md"), "w") as fh:
            fh.write("no front matter at all")
        with open(os.path.join(d, "r", "badjson.md"), "w") as fh:
            fh.write("---\nrepo: {nope\n---\n")
        with open(os.path.join(d, "r", "big.md"), "wb") as fh:
            fh.write(b"x" * 200)
        old = cf.MAX_NODE_BYTES
        cf.MAX_NODE_BYTES = 100
        try:
            nodes, report = cf.load(["r"], d)
        finally:
            cf.MAX_NODE_BYTES = old
        self.assertEqual((len(nodes), report["files"], report["skipped_malformed"], report["skipped_too_big"]), (0, 3, 2, 1))

    def test_a_repo_name_that_walks_out_is_refused(self):
        d = tempfile.mkdtemp()
        for name in ("../x", "..", "a/b"):
            with self.assertRaises(sp.PathRefused):
                cf.load([name], d)

    def test_an_unknown_license_class_is_the_strict_side_not_a_crash(self):
        a = node("a", "MIT-ish", [sym("f", "no error handling (3 calls)", "documented", ["x1", "x2", "x3"])])
        b = node("b", "PERMISSIVE", [sym("g", "undocumented", "handles errors", ["x1", "x2"])])
        p = cf.propose([a, b])[0]
        self.assertEqual(p["strictest_license_class"], "NO_LICENSE_FILE")

    def test_the_search_does_not_grow_with_the_square_of_unrelated_symbols(self):
        """6,000 weak functions that share no call with anything: the old all-pairs loop made 36 million comparisons."""
        nodes = [node("r%d" % (i % 7), "PERMISSIVE", [sym("f%d" % i, "no error handling (3 calls)", "documented", ["only_%d_a" % i, "only_%d_b" % i, "only_%d_c" % i])]) for i in range(6000)]
        t0 = time.time()
        self.assertEqual(cf.propose(nodes), [])
        self.assertLess(time.time() - t0, 5)

    def test_top_is_exact_ordered_deterministic_and_bounded(self):
        base = [node("a", "PERMISSIVE", [sym("weak%d" % i, "no error handling (3 calls)", "documented", ["c1", "c2", "c3"], lines=10 + i)]) for i in range(5)]
        strong = [node("b", "PERMISSIVE", [sym("strong%d" % i, "undocumented", "handles errors", ["c1", "c2", "c3"], lines=10 + i)]) for i in range(5)]
        every = cf.propose(base + strong, top=1000)
        self.assertEqual([c["score"] for c in every], sorted((c["score"] for c in every), reverse=True))
        for k in (0, 1, 3):
            got = cf.propose(base + strong, top=k)
            self.assertEqual(got, every[:k])
        self.assertEqual(cf.propose(base + strong, top=3), cf.propose(base + strong, top=3))
        for bad in (-1, True, 1.5, "3", None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                cf.propose(base, top=bad)

    def test_too_many_functions_for_one_run_is_a_clear_refusal(self):
        old = cf.MAX_POOL
        cf.MAX_POOL = 5
        try:
            with self.assertRaises(ValueError):
                cf.propose([node("a", "PERMISSIVE", [sym("f%d" % i, "undocumented", "documented", ["c"]) for i in range(10)])])
        finally:
            cf.MAX_POOL = old

    def test_same_name_is_a_duplicate_not_a_complement_and_other_languages_never_pair(self):
        a = node("a", "PERMISSIVE", [sym("f", "no error handling (3 calls)", "documented", ["c1", "c2", "c3"])])
        same = node("b", "PERMISSIVE", [sym("f", "undocumented", "handles errors", ["c1", "c2", "c3"])])
        go = node("c", "PERMISSIVE", [sym("g", "undocumented", "handles errors", ["c1", "c2", "c3"])], lang="go")
        self.assertEqual(cf.propose([a, same, go]), [])


def write_card(d, repo, text):
    with open(os.path.join(d, repo + ".jsonl"), "w", encoding="utf-8") as f:
        f.write(text)


class Verifier(unittest.TestCase):
    def setUp(self):
        cv._cache.clear()
        self.d = tempfile.mkdtemp()

    def good(self, d=None, repo="good", **kw):
        c = {"kind": "repo_node", "license_class": "PERMISSIVE", "audit_status": "COMPLETE", "score_dimensions": {"test_share_of_code": 0.3, "graph_edges_extracted_not_inferred": 0.9}}
        c.update(kw)
        write_card(d or self.d, repo, json.dumps(c) + "\n")

    def test_a_repo_name_that_walks_out_never_reads_a_file_elsewhere(self):
        elsewhere = tempfile.mkdtemp()
        self.good(elsewhere, "stolen")
        cards_dir = os.path.join(self.d, "cards")
        os.makedirs(cards_dir)
        for name in ("../stolen", "..\\stolen", "a/../../stolen", "/etc/passwd"):
            r = cv.verify_candidate({"repo": name}, cards_dir)
            self.assertFalse(r["passes"], name)
            self.assertIn("unsafe", r["why"])
        r = cv.verify_candidate({"weak_symbol": {"repo": "../stolen"}, "strong_symbol": {"repo": "x"}}, cards_dir)
        self.assertFalse(r["passes"])

    def test_a_card_that_is_not_a_repo_card_or_not_json_verifies_nothing(self):
        for text in ("{broken", "[1,2]", '"string"', json.dumps({"kind": "code_node", "license_class": "PERMISSIVE"}) + "\n", "", "\n"):
            write_card(self.d, "odd", text)
            cv._cache.clear()
            r = cv.verify_node("odd", 5, self.d)
            self.assertFalse(r["passes"], repr(text)[:30])
            self.assertIn("nothing verified", r["why"])

    def test_non_numeric_scores_count_as_not_passed_instead_of_crashing(self):
        self.good(score_dimensions={"test_share_of_code": "lots", "graph_edges_extracted_not_inferred": None})
        r = cv.verify_node("good", 5, self.d)
        self.assertFalse(r["passes"])
        self.assertIn("c3_test_evidence", r["why"])
        self.good(score_dimensions="not a dict")
        cv._cache.clear()
        self.assertFalse(cv.verify_node("good", 5, self.d)["passes"])
        self.good(score_dimensions={"test_share_of_code": True, "graph_edges_extracted_not_inferred": float("nan")})
        cv._cache.clear()
        self.assertFalse(cv.verify_node("good", 5, self.d)["passes"])

    def test_the_cache_is_never_served_stale(self):
        self.good()
        self.assertTrue(cv.verify_node("good", 5, self.d)["passes"])
        time.sleep(0.02)
        self.good(license_class="STRONG_COPYLEFT")
        self.assertFalse(cv.verify_node("good", 5, self.d)["passes"])                    # the same folder, a changed card
        other = tempfile.mkdtemp()
        self.good(other, license_class="STRONG_COPYLEFT")
        self.assertFalse(cv.verify_node("good", 5, other)["passes"])                     # another folder, the same repo name
        self.good(other, license_class="PERMISSIVE")
        self.assertTrue(cv.verify_node("good", 5, other)["passes"])

    def test_two_folders_with_the_same_repo_name_never_share_a_cache_entry(self):
        """Same repo name, same card size, same modification time, different folders: only the folder in the key tells them apart."""
        a, b = tempfile.mkdtemp(), tempfile.mkdtemp()
        self.good(a, license_class="PERMISSIVE")
        self.good(b, license_class="PERMISSIVF")
        stamp = time.time() - 100
        for folder in (a, b):
            os.utime(os.path.join(folder, "good.jsonl"), (stamp, stamp))
        self.assertEqual(os.path.getsize(os.path.join(a, "good.jsonl")), os.path.getsize(os.path.join(b, "good.jsonl")))
        self.assertTrue(cv.verify_node("good", 5, a)["passes"])
        self.assertFalse(cv.verify_node("good", 5, b)["passes"])

    def test_degree_must_be_a_real_count_and_unknown_is_not_connected(self):
        self.good()
        for d in (None, True, -3, 1.5, "5"):
            self.assertFalse(cv.verify_node("good", d, self.d)["passes"], repr(d))
        self.assertTrue(cv.verify_node("good", 2, self.d)["passes"])

    def test_candidate_shapes_that_are_not_objects_are_refused_cleanly(self):
        for c in (None, [], "repo", 5, {}, {"repo": None}, {"weak_symbol": "x", "strong_symbol": "y"}):
            r = cv.verify_candidate(c, self.d)
            self.assertFalse(r["passes"], repr(c))
        with self.assertRaises(ValueError):
            cv.verify_node("good", 5, None)


if __name__ == "__main__":
    unittest.main()
