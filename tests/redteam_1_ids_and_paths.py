"""RED TEAM PASS 1 (dkg-lattice): id collisions, silent crosswalk drift, and every way a name or path can leave the folder it belongs in."""
import hashlib
import os
import sqlite3
import tempfile
import unittest

from vega_dkg import safe_paths as sp
from vega_dkg import vega_id as v


def row(i, label="f", loc="L1", path="a/b.py", uni="repo1", kind="function"):
    return dict(local_id=i, universe=uni, path=path, kind=kind, label=label, location=loc)


class IdCollisions(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.cw = v.Crosswalk(os.path.join(self.d.name, "cw.db"))

    def tearDown(self):
        self.cw.close()
        self.d.cleanup()

    def test_a_separator_inside_a_field_cannot_make_two_nodes_one(self):
        """The id is a hash of fields joined with '|'. ('a|b', 'c') and ('a', 'b|c') used to join to the same text."""
        self.assertNotEqual(v.vega_id("u", "a|b", "k", "c", ""), v.vega_id("u", "a", "k", "b|c", ""))
        self.assertNotEqual(v.vega_id("u", "p", "k", "x|y", "z"), v.vega_id("u", "p", "k", "x", "y|z"))
        self.assertNotEqual(v.vega_id("u", "a%7Cb", "k", "c", ""), v.vega_id("u", "a|b", "k", "c", ""))

    def test_ids_for_ordinary_fields_are_exactly_what_they_always_were(self):
        want = "vn1_" + hashlib.sha256("repo1|a/b.py|function|f|l1|0".encode()).hexdigest()[:26]
        self.assertEqual(v.vega_id("repo1", "a/b.py", "function", "f", "L1", 0), want)

    def test_two_batches_cannot_hand_the_same_id_to_two_different_nodes(self):
        self.cw.add_many("L", [row("first")])
        self.cw.add_many("L", [row("second")])                       # same logical tuple, a later batch
        a, b = self.cw.lookup("L", "first"), self.cw.lookup("L", "second")
        self.assertNotEqual(a, b)
        s = self.cw.stats()[0]
        self.assertEqual((s["nodes"], s["distinct_vega_ids"], s["in_collision_groups"]), (2, 2, 2))

    def test_a_row_that_changed_is_reported_not_silently_ignored(self):
        self.cw.add_many("L", [row("k", label="one")])
        first = self.cw.lookup("L", "k")
        rep = self.cw.add_many("L", [row("k", label="two"), row("j")])
        self.assertEqual((rep["added"], rep["unchanged"], len(rep["conflicts"])), (1, 0, 1))
        self.assertEqual(rep["conflicts"][0]["local_id"], "k")
        self.assertEqual(self.cw.lookup("L", "k"), first)
        rep2 = self.cw.add_many("L", [row("k", label="one")])
        self.assertEqual((rep2["added"], rep2["unchanged"], rep2["conflicts"]), (0, 1, []))

    def test_the_database_itself_refuses_two_nodes_with_one_id_in_a_layer(self):
        self.cw.add_many("L", [row("a")])
        vid = self.cw.lookup("L", "a")
        with self.assertRaises(sqlite3.IntegrityError):
            self.cw.con.execute("insert into crosswalk(layer, local_id, vega_id, universe, collision_group, base_key) values ('L','other',?,'u',1,'x')", (vid,))

    def test_bad_rows_and_values_are_refused(self):
        for rows in ([None], [5], [{"label": "no local id"}], [{"local_id": "x", "label": "y"}, "str"]):
            with self.assertRaises(v.IdRefused, msg=repr(rows)):
                self.cw.add_many("L", rows)
        for layer in ("", None, 5):
            with self.assertRaises(v.IdRefused):
                self.cw.add_many(layer, [row("a")])
        for o in (-1, True, 1.5, "0", None):
            with self.assertRaises(v.IdRefused, msg=repr(o)):
                v.vega_id("u", "p", "k", "l", "", o)
        with self.assertRaises(v.IdRefused):
            v.vega_id("u", "p", "k", "x" * (v.MAX_FIELD + 1), "")
        self.assertTrue(v.vega_id(None, None, None, None, None).startswith("vn1_"))
        self.assertEqual(self.cw.stats(), [])

    def test_a_failed_batch_leaves_nothing_half_written(self):
        self.cw.add_many("L", [row("seed", label="seed")])
        bad = [row("ok1", label="ok1"), row("ok2", label="ok2"), None]
        with self.assertRaises(v.IdRefused):
            self.cw.add_many("L", bad)
        self.assertIsNone(self.cw.lookup("L", "ok1"))

    def test_an_older_database_without_the_new_column_still_opens_and_keeps_its_ids(self):
        p = os.path.join(self.d.name, "old.db")
        con = sqlite3.connect(p)
        con.execute("create table crosswalk(layer text not null, local_id text not null, vega_id text not null, universe text, collision_group integer not null default 1, primary key(layer, local_id))")
        con.execute("insert into crosswalk values ('L','old','vn1_legacy',  'u', 1)")
        con.commit()
        con.close()
        with v.Crosswalk(p) as cw:
            self.assertEqual(cw.lookup("L", "old"), "vn1_legacy")
            cw.add_many("L", [row("new", label="brand new")])
            self.assertEqual(len(cw.stats()), 1)


class Names(unittest.TestCase):
    def test_a_repo_name_is_one_plain_component(self):
        for ok in ("graal-master", "llm.c", "Lib-master", "a b", "repo_1", "x+y", "name@2"):
            self.assertEqual(sp.safe_name(ok), ok)
        for bad in ("", ".", "..", "../x", "a/b", "a\\b", "..\\x", "/etc", "C:\\x", "a..b", ".hidden", "-lead", " lead", "a\x00b", "a\nb", "x" * 201, None, 5, ["a"], b"a"):
            with self.assertRaises(sp.PathRefused, msg=repr(bad)):
                sp.safe_name(bad)


class Containment(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.root = os.path.join(self.d.name, "root")
        os.makedirs(os.path.join(self.root, "sub"))
        self.outside = os.path.join(self.d.name, "outside.txt")
        open(self.outside, "w").write("secret")

    def tearDown(self):
        self.d.cleanup()

    def test_traversal_absolute_paths_and_nul_are_refused(self):
        for parts in (("..", "outside.txt"), ("sub", "..", "..", "outside.txt"), (self.outside,), ("sub/../../outside.txt",), ("a\x00b",), (5,)):
            with self.assertRaises(sp.PathRefused, msg=repr(parts)):
                sp.contained(self.root, *parts)
        self.assertTrue(sp.contained(self.root, "sub", "ok.txt").startswith(os.path.realpath(self.root)))

    def test_a_sibling_folder_with_the_same_prefix_is_outside(self):
        sib = os.path.join(self.d.name, "root-evil")
        os.makedirs(sib)
        with self.assertRaises(sp.PathRefused):
            sp.contained(self.root, "..", "root-evil", "x")

    def test_a_symlink_that_points_outside_is_refused(self):
        link = os.path.join(self.root, "sub", "link.txt")
        try:
            os.symlink(self.outside, link)
        except (OSError, NotImplementedError, AttributeError):
            self.skipTest("this account cannot create symlinks")
        with self.assertRaises(sp.PathRefused):
            sp.contained(self.root, "sub", "link.txt")

    def test_a_directory_junction_that_points_outside_is_refused(self):
        """Windows folder junctions need no special privilege, so this runs where a symlink test cannot."""
        if os.name != "nt":
            self.skipTest("junctions are a Windows feature")
        import subprocess
        outside_dir = os.path.join(self.d.name, "outside_dir")
        os.makedirs(outside_dir)
        with open(os.path.join(outside_dir, "loot.py"), "w") as fh:
            fh.write("def loot(): pass")
        link = os.path.join(self.root, "sub", "jn")
        r = subprocess.run(["cmd", "/c", "mklink", "/J", link, outside_dir], capture_output=True, text=True)
        if r.returncode != 0:
            self.skipTest("could not create a junction: " + r.stderr.strip())
        with self.assertRaises(sp.PathRefused):
            sp.contained(self.root, "sub", "jn", "loot.py")

    def test_read_capped_refuses_a_big_file_and_reads_a_small_one(self):
        p = os.path.join(self.root, "big.bin")
        open(p, "wb").write(b"x" * 100)
        self.assertEqual(sp.read_capped(p, 100), b"x" * 100)
        with self.assertRaises(sp.PathRefused):
            sp.read_capped(p, 99)

    def test_atomic_write_never_leaves_a_half_file_or_a_temp_file(self):
        p = os.path.join(self.root, "sub", "f.txt")
        sp.atomic_write(p, "one")
        real = os.replace
        os.replace = lambda a, b: (_ for _ in ()).throw(OSError("disk full"))
        try:
            with self.assertRaises(OSError):
                sp.atomic_write(p, "two")
        finally:
            os.replace = real
        self.assertEqual(open(p, encoding="utf-8").read(), "one")
        self.assertEqual([n for n in os.listdir(os.path.dirname(p)) if n.endswith(".tmp")], [])


if __name__ == "__main__":
    unittest.main()
