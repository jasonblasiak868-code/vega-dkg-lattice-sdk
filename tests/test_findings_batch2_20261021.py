"""Findings from a line-by-line source read, 2026-10-21, batch 2 (combine_finder, catalog, md_nodes). Each test failed before its fix."""
import json
import os
import tempfile
import time
import unittest

from test_dkg import make_library
from vega_dkg import catalog
from vega_dkg import combine_finder as cf
from vega_dkg import md_nodes

FRONT = '---\nvega_id: "x"\nrepo: "r"\npath: "a.py"\nlanguage: "python"\nlicense_class: "PERMISSIVE"\n---\n\n# a.py\n'


def sym(name, weak, strong, calls, lines=10):
    return ("## function `%s` L1-%d  (vn1_%s)\n- scores: tested_by_name=True, fan_in_by_name=2\n- weaknesses: %s\n- strengths: %s\n- calls: %s\n- text_hash: abc\n\n"
            % (name, lines, name, weak, strong, calls))


def write_node(root, repo, rel, text):
    p = os.path.join(root, repo, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "w", encoding="utf-8", newline="\n").write(text)
    return p


class A_CombineFinder(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.d.cleanup()

    def test_a_file_without_front_matter_is_malformed_even_if_it_contains_dashes(self):
        p = write_node(self.d.name, "r", "x.md", "intro\n---\nx\n---\n" + sym("f", "no error handling", "none", "a, b"))
        self.assertIsNone(cf.parse_node(p))
        fake = 'junk\npath: "a.py"\nrepo: "r"\nlanguage: "python"\n---\n' + sym("f", "no error handling", "none", "a, b")
        self.assertIsNone(cf.parse_node(write_node(self.d.name, "r", "late.md", fake)))          # front matter keys that do not open the file are not front matter

    def test_front_matter_without_the_required_keys_is_malformed(self):
        text = "---\nnote: only this\n---\n\n# x\n" + sym("f", "no error handling", "none", "a, b")
        p = write_node(self.d.name, "r", "k.md", text)
        self.assertIsNone(cf.parse_node(p))

    def test_an_unknown_callee_is_not_a_shared_call(self):
        write_node(self.d.name, "r", "a.py.md", FRONT + sym("weakf", "no error handling (3 calls)", "none", "?") + sym("strongf", "none", "handles errors", "?"))
        nodes, _ = cf.load(["r"], self.d.name)
        self.assertEqual(cf.propose(nodes), [])

    def test_a_call_name_shared_by_too_many_functions_does_not_cost_a_pair_each(self):
        old = cf.MAX_POSTING
        cf.MAX_POSTING = 50
        try:
            body = "".join(sym("f%d" % i, "no error handling (3 calls)" if i % 2 else "none", "handles errors" if i % 2 == 0 else "none", "len") for i in range(300))
            write_node(self.d.name, "r", "a.py.md", FRONT + body)
            nodes, _ = cf.load(["r"], self.d.name)
            t0 = time.time()
            got = cf.propose(nodes)
            self.assertLess(time.time() - t0, 2.0)
            self.assertEqual(got, [])                                  # "len" names too many functions to say anything about any pair
            rare = FRONT + sym("weakr", "no error handling (3 calls)", "none", "len, rareone") + sym("strongr", "none", "handles errors", "len, rareone")
            write_node(self.d.name, "r2", "b.py.md", rare.replace('repo: "r"', 'repo: "r2"'))
            nodes2, _ = cf.load(["r2"], self.d.name)
            self.assertTrue(cf.propose(nodes2))                        # a rarer shared call still finds the pair
        finally:
            cf.MAX_POSTING = old

    def test_bad_arguments_are_refused(self):
        for kw in ({"min_overlap": "x"}, {"min_overlap": True}, {"min_overlap": -0.5}, {"min_overlap": 2}, {"dims": "long"}, {"dims": ["bogus"]}):
            with self.assertRaises(ValueError, msg=repr(kw)):
                cf.propose([], **kw)

    def test_a_repo_listed_twice_is_read_once(self):
        make_library(os.path.join(self.d.name, "lib"))
        md_nodes.build_repo("r1", os.path.join(self.d.name, "lib"), os.path.join(self.d.name, "out"), {"r1": {"license_class": "PERMISSIVE"}})
        once, rep1 = cf.load(["r1"], os.path.join(self.d.name, "out"))
        twice, rep2 = cf.load(["r1", "r1"], os.path.join(self.d.name, "out"))
        self.assertEqual((len(once), rep1["files"]), (len(twice), rep2["files"]))


class B_Catalog(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.d.cleanup()

    def test_a_node_with_a_forged_path_line_does_not_stop_the_catalog(self):
        text = '---\nvega_id: "x"\nrepo: "r"\npath: "a"b"\nlanguage: "python"\nlicense_class: "PERMISSIVE"\n---\n\n# x\n' + sym("fetch_things", "none", "handles errors", "get")
        write_node(self.d.name, "r", "a.py.md", text)
        got = list(catalog.symbols_of(os.path.join(self.d.name, "r")))
        self.assertEqual([g[1] for g in got], ["fetch_things"])
        self.assertEqual(got[0][0], "a.py.md")                         # falls back to the file's own relative path

    def test_both_catalog_files_are_written_atomically(self):
        lib = os.path.join(self.d.name, "lib", "r1")
        os.makedirs(lib)
        open(os.path.join(lib, "README.md"), "w", encoding="utf-8").write("a knowledge graph tool")
        open(os.path.join(self.d.name, "matrix.json"), "w", encoding="utf-8").write(json.dumps([{"repo": "r1", "license_class": "PERMISSIVE"}]))
        real = catalog.sp.atomic_write
        written = []

        def spy(path, text):
            written.append(os.path.basename(path))
            return real(path, text)
        catalog.sp.atomic_write = spy
        try:
            catalog.build(os.path.join(self.d.name, "lib"), os.path.join(self.d.name, "md"), os.path.join(self.d.name, "matrix.json"), None, os.path.join(self.d.name, "out"))
        finally:
            catalog.sp.atomic_write = real
        self.assertIn("LIBRARY_IMPROVEMENT_CATALOG.jsonl", written)
        self.assertEqual(written.count("LIBRARY_IMPROVEMENT_CATALOG.md"), 1)
        md = open(os.path.join(self.d.name, "out", "LIBRARY_IMPROVEMENT_CATALOG.md"), encoding="utf-8").read()
        self.assertIn("Repos with no capability tag", md)


class C_MdNodes(unittest.TestCase):
    def test_a_callee_that_cannot_be_named_is_not_recorded_as_a_call(self):
        syms = md_nodes.py_symbols("def f():\n    x = [print]\n    x[0]()\n    helper()\n")
        self.assertEqual([s["calls"] for s in syms], [["helper"]])

    def test_missing_matrix_fields_are_not_scored_in_the_front_matter(self):
        d = tempfile.mkdtemp()
        make_library(os.path.join(d, "lib"))
        md_nodes.build_repo("r1", os.path.join(d, "lib"), os.path.join(d, "out"), {})
        text = open(os.path.join(d, "out", "r1", "a.py.md"), encoding="utf-8").read()
        self.assertIn('use_boundary: "not_scored"', text)
        self.assertIn('public_build: "not_scored"', text)
        self.assertIn('license_class: "UNKNOWN"', text)


if __name__ == "__main__":
    unittest.main()
