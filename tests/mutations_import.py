"""Mutation check for knowledge_import.py: each rule removed in a COPY must make tests/test_knowledge_import.py fail."""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent
F = "knowledge_import.py"
MUTATIONS = [
    ("over-long lines are skipped", F, 'if len(raw) > max_line and not raw.endswith(b"\\n"):', "if False:"),
    ("deprecated statements dropped", F, 'if st.get("rank") == "deprecated":', "if False:"),
    ("only statements with a value", F, 'if snak.get("snaktype") != "value":', "if False:"),
    ("only item-valued statements", F, 'if dv.get("type") != "wikibase-entityid":', "if False:"),
    ("only items", F, 'if entity.get("type") != "item" or not isinstance(qid, str)', 'if False or not isinstance(qid, str)'),
    ("class filter", F, "if flt.instance_of is not None and not any(", "if False and not any("),
    ("qid filter", F, "if flt.qids is not None and qid not in flt.qids:", "if False:"),
    ("a missing label is not invented", F, "or next(iter(labels.values()), dkgcards.NS)", "or next(iter(labels.values()), qid)"),
    ("unreferenced is said", F, '"referenced": n > 0', '"referenced": True'),
    ("no abstract text from openalex", F, '"abstract_present": bool(work.get("abstract_inverted_index"))', '"abstract_present": work.get("abstract_inverted_index")'),
    ("duplicates once", F, 'if n["vega_id"] in seen:', "if False:"),
    ("parts roll over", F, "if self._fh is not None and self._bytes + len(line) > self.max:", "if False:"),
    ("record cap", F, "if len(line) > MAX_RECORD:", "if False:"),
    ("part size limit", F, "not 1024 <= max_bytes <= HARD_PART", "False"),
    ("stub nodes", F, "    if stubs:  ", "    if False:  "),
    ("parts re-hashed", F, 'elif sha256_file(f) != p["sha256"] or os.path.getsize(f) != p["bytes"]:', "elif False:"),
    ("batch hash re-derived", F, 'if manifest["batch_sha256"] != batch_sha256(manifest["parts"]):', "if False:"),
    ("a commitment is required", F, 'approved = commit_check(req["action"], req["params"]) is True', "approved = True"),
    ("count-back", F, "if sent != expect or stored != sent:", "if False:"),
    ("loader must report a count", F, "if isinstance(n, bool) or not isinstance(n, int) or n < 0:", "if False:"),
    ("parts verified before loading", F, "    bad = verify_parts(manifest, out_dir)\n    if bad:", "    bad = verify_parts(manifest, out_dir)\n    if False:"),
]
if __name__ != "__main__":
    MUTATIONS = []
survivors = []
for name, fname, old, new in MUTATIONS:
    tmp = pathlib.Path(tempfile.mkdtemp())
    shutil.copytree(REPO / "src" / "vega_dkg", tmp / "vega_dkg")
    f = tmp / "vega_dkg" / fname
    text = f.read_text(encoding="utf-8")
    if old not in text:
        print("CANNOT APPLY", name)
        survivors.append(name + " (could not apply)")
        continue
    f.write_text(text.replace(old, new, 1), encoding="utf-8")
    env = dict(os.environ)
    env["PYTHONPATH"] = str(tmp) + os.pathsep + env.get("PYTHONPATH", "")
    r = subprocess.run([sys.executable, "-W", "ignore", "-m", "unittest", "test_knowledge_import"], capture_output=True, text=True, env=env, cwd=str(REPO / "tests"), timeout=600)
    print(("killed   " if r.returncode != 0 else "SURVIVED ") + name, flush=True)
    if r.returncode == 0:
        survivors.append(name)
    shutil.rmtree(tmp, ignore_errors=True)
print("survivors:", survivors or "none")
