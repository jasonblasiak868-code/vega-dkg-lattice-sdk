"""Importing open public knowledge into the DKG: reading, filtering, parts and their size limit, licences, the batch commitment, verification and count-back loading."""
import bz2
import copy
import gzip
import hashlib
import json
import os
import pathlib
import tempfile
import unittest

from vega_dkg import cards as dkgcards, knowledge_import as K


def item(qid, label, instance_of=("Q5",), extra_claims=None, refs=1, rank="normal", snaktype="value", labels=None):
    def stmt(prop, target, r=refs, rk=rank, sk=snaktype):
        s = {"mainsnak": {"snaktype": sk, "property": prop}, "rank": rk, "references": [{"snaks": {}}] * r}
        if sk == "value":
            s["mainsnak"]["datavalue"] = {"type": "wikibase-entityid", "value": {"entity-type": "item", "id": target}}
        return s
    claims = {"P31": [stmt("P31", t) for t in instance_of]}
    for prop, target in (extra_claims or []):
        claims.setdefault(prop, []).append(stmt(prop, target))
    return {"id": qid, "type": "item", "labels": labels if labels is not None else {"en": {"language": "en", "value": label}}, "descriptions": {"en": {"language": "en", "value": "about " + label}}, "claims": claims}


def write_dump(path, objs, array=True, gz=False, bz=False):
    lines = [json.dumps(o, ensure_ascii=False) for o in objs]
    text = "[\n" + ",\n".join(lines) + "\n]\n" if array else "\n".join(lines) + "\n"
    data = text.encode("utf-8")
    if gz:
        data = gzip.compress(data)
    if bz:
        data = bz2.compress(data)
    pathlib.Path(path).write_bytes(data)


class Reading(unittest.TestCase):
    def setUp(self):
        self.d = pathlib.Path(tempfile.mkdtemp())
        self.objs = [item("Q1", "Alpha"), item("Q2", "Beta", ("Q5",), [("P50", "Q1")]), item("Q3", "Gamma", ("Q7",))]

    def test_every_dump_format_reads_the_same(self):
        outs = []
        for name, kw in (("a.json", dict(array=True)), ("b.jsonl", dict(array=False)), ("c.json.gz", dict(array=True, gz=True)), ("d.json.bz2", dict(array=True, bz=True))):
            write_dump(self.d / name, self.objs, **kw)
            m = K.import_dump(self.d / name, "wikidata", self.d / ("out_" + name))
            outs.append((m["counts"]["nodes"], m["counts"]["edges"], m["counts"]["stubs"]))
        self.assertEqual(len(set(outs)), 1)
        self.assertEqual(outs[0], (3, 4, 2))                                         # three items, four statements, stubs for Q5 and Q7

    def test_bad_lines_long_lines_blank_lines_and_a_byte_order_mark_are_counted_not_fatal(self):
        raw = b"\xef\xbb\xbf[\n" + json.dumps(self.objs[0]).encode() + b",\nnot json at all,\n\n" + b'{"id": "Q9", "type": "property"},\n' + b'{"x": ' + b"9" * 200 + b"},\n" + json.dumps(self.objs[1]).encode() + b"\n]\n"
        (self.d / "x.json").write_bytes(raw)
        stats = {}
        got = list(K.iter_json_lines(self.d / "x.json", stats, max_line=150))
        self.assertEqual(stats.get("bad_json"), 1)
        self.assertEqual(stats.get("too_long"), 3)                                 # the 200-digit line and the two item lines are over a 150-byte limit
        m = K.import_dump(self.d / "x.json", "wikidata", self.d / "o")
        self.assertEqual(m["counts"]["nodes"] >= 2, True)
        self.assertEqual(m["skipped"]["bad_json"], 1)
        self.assertEqual(m["skipped"]["skipped_shape"], 2)                          # the property entity and the bare object

    def test_a_line_over_the_limit_is_reported_and_the_next_lines_still_read(self):
        big = item("Q50", "Big")
        big["claims"]["P999"] = [{"mainsnak": {"snaktype": "somevalue"}, "rank": "normal"}] * 5000
        write_dump(self.d / "big.json", [self.objs[0], big, self.objs[1]], array=False)
        stats = {}
        got = [o["id"] for o in K.iter_json_lines(self.d / "big.json", stats, max_line=2000)]
        self.assertEqual(got, ["Q1", "Q2"])
        self.assertEqual(stats["too_long"], 1)


class Records(unittest.TestCase):
    def setUp(self):
        self.d = pathlib.Path(tempfile.mkdtemp())

    def run_one(self, obj, **flt):
        write_dump(self.d / "one.jsonl", [obj], array=False)
        m = K.import_dump(self.d / "one.jsonl", "wikidata", self.d / ("o%d" % len(os.listdir(self.d))), K.Filter(**flt))
        recs = []
        for p in m["parts"]:
            recs += [json.loads(l) for l in open(self.d / ("o%d" % (len(os.listdir(self.d)) - 1)) / p["file"], encoding="utf-8")]
        return m, recs

    def test_nodes_carry_label_licence_taint_and_a_valid_dna_hash(self):
        m, recs = self.run_one(item("Q42", "Douglas Adams", ("Q5",), [("P106", "Q36180")]))
        node = [r for r in recs if r["kind"] == "wd_item" and not r.get("stub")][0]
        self.assertEqual((node["label"], node["source_id"], node["instance_of"]), ("Douglas Adams", "Q42", ["Q5"]))
        self.assertEqual(node["inherited"], {"license_class": "PERMISSIVE", "taint_if_used": False, "license": "CC0-1.0", "source": "wikidata"})
        self.assertTrue(node["extracted"])
        body = {k: v for k, v in node.items() if k != "dna_hash"}
        self.assertEqual(dkgcards.h(body), node["dna_hash"])
        edges = [r for r in recs if r["kind"] == "edge"]
        self.assertEqual(sorted(e["relation"] for e in edges), ["P106", "P31"])
        self.assertTrue(all(e["referenced"] and e["references"] == 1 for e in edges))
        self.assertFalse(m["tainted"])

    def test_unreferenced_statements_are_kept_and_labelled_deprecated_and_valueless_ones_are_dropped(self):
        obj = item("Q10", "Ten", ("Q5",), [], refs=0)
        obj["claims"]["P2"] = [{"mainsnak": {"snaktype": "value", "datavalue": {"type": "wikibase-entityid", "value": {"id": "Q20"}}}, "rank": "deprecated"},
                               {"mainsnak": {"snaktype": "somevalue"}, "rank": "normal"}, {"mainsnak": {"snaktype": "novalue"}, "rank": "normal"},
                               {"mainsnak": {"snaktype": "value", "datavalue": {"type": "string", "value": "text"}}, "rank": "normal"}, {"broken": True}, None,
                               {"mainsnak": {"snaktype": "somevalue", "datavalue": {"type": "wikibase-entityid", "value": {"id": "Q98"}}}, "rank": "normal"},        # not a value, whatever it carries
                               {"mainsnak": {"snaktype": "value", "datavalue": {"type": "string", "value": {"id": "Q99"}}}, "rank": "normal"}]                      # a string that merely looks like an entity
        m, recs = self.run_one(obj)
        edges = [r for r in recs if r["kind"] == "edge"]
        self.assertEqual([(e["relation"], e["referenced"]) for e in edges], [("P31", False)])

    def test_languages_fall_back_and_missing_labels_are_not_invented(self):
        m, recs = self.run_one(item("Q11", "x", labels={"fr": {"language": "fr", "value": "Onze"}}), languages=("en", "fr"))
        node = [r for r in recs if r["kind"] == "wd_item" and not r.get("stub")][0]
        self.assertEqual(node["label"], "Onze")
        m, recs = self.run_one(item("Q12", "x", labels={}))
        node = [r for r in recs if r["kind"] == "wd_item" and not r.get("stub")][0]
        self.assertEqual(node["label"], dkgcards.NS)

    def test_filters_by_qid_by_class_and_by_count(self):
        objs = [item("Q1", "A", ("Q5",)), item("Q2", "B", ("Q9",)), item("Q3", "C", ("Q5",)), item("Q4", "D", ("Q5",))]
        write_dump(self.d / "f.jsonl", objs, array=False)

        def nodes(**flt):
            m = K.import_dump(self.d / "f.jsonl", "wikidata", self.d / ("f%d" % len(os.listdir(self.d))), K.Filter(**flt), stubs=False)
            return m["counts"]["nodes"]
        self.assertEqual(nodes(), 4)
        self.assertEqual(nodes(qids=["Q1", "Q4"]), 2)
        self.assertEqual(nodes(instance_of=["Q5"]), 3)
        self.assertEqual(nodes(instance_of=["Q5"], max_nodes=2), 2)
        self.assertEqual(nodes(qids=["Q404"]), 0)
        for bad in ({"languages": []}, {"languages": [""]}, {"max_nodes": 0}, {"max_nodes": True}):
            with self.assertRaises(K.ImportRefused):
                K.Filter(**bad)

    def test_duplicates_in_the_dump_are_kept_once_and_counted(self):
        write_dump(self.d / "dup.jsonl", [item("Q1", "A"), item("Q1", "A again")], array=False)
        m = K.import_dump(self.d / "dup.jsonl", "wikidata", self.d / "od", stubs=False)
        self.assertEqual((m["counts"]["nodes"], m["counts"]["duplicates"]), (1, 1))

    def test_ids_are_the_same_every_run_and_edges_point_at_real_ids(self):
        write_dump(self.d / "s.jsonl", [item("Q1", "A", ("Q5",)), item("Q5", "human", ("Q9",))], array=False)
        runs = [K.import_dump(self.d / "s.jsonl", "wikidata", self.d / ("r%d" % i)) for i in (1, 2)]
        self.assertEqual(runs[0]["batch_sha256"], runs[1]["batch_sha256"])
        recs = [json.loads(l) for p in runs[0]["parts"] for l in open(self.d / "r1" / p["file"], encoding="utf-8")]
        ids = {r["vega_id"] for r in recs if r["kind"] != "edge"}
        for e in (r for r in recs if r["kind"] == "edge"):
            self.assertIn(e["src"], ids)
            self.assertIn(e["dst"], ids)                                             # stubs make sure no edge points at nothing
        self.assertTrue(any(r.get("stub") for r in recs))


class OtherSources(unittest.TestCase):
    def test_openalex_works_become_papers_with_citation_and_author_edges_and_no_abstract_text(self):
        d = pathlib.Path(tempfile.mkdtemp())
        work = {"id": "https://openalex.org/W100", "title": "On Governance", "publication_year": 2024, "doi": "https://doi.org/10.1/x", "type": "article",
                "abstract_inverted_index": {"hello": [0]}, "referenced_works": ["https://openalex.org/W7", "https://openalex.org/W8"],
                "authorships": [{"author": {"id": "https://openalex.org/A1", "display_name": "Ada L."}}, {"author": None}, {}]}
        write_dump(d / "w.jsonl", [work, {"bad": 1}], array=False)
        m = K.import_dump(d / "w.jsonl", "openalex", d / "o")
        recs = [json.loads(l) for p in m["parts"] for l in open(d / "o" / p["file"], encoding="utf-8")]
        paper = [r for r in recs if r["kind"] == "paper" and r["source_id"] == "W100"][0]
        self.assertTrue(paper["abstract_present"])
        self.assertNotIn("hello", json.dumps(recs))
        rel = sorted(r["relation"] for r in recs if r["kind"] == "edge")
        self.assertEqual(rel, ["AUTHORED_BY", "CITES", "CITES"])
        self.assertEqual(m["skipped"]["skipped_shape"], 1)

    def test_arxiv_records_keep_an_abstract_hash_not_the_text(self):
        d = pathlib.Path(tempfile.mkdtemp())
        rec = {"id": "2401.00001", "title": "A Title", "authors": "A. B., C. D.", "categories": "cs.AI cs.CR", "abstract": "A long abstract text.", "update_date": "2024-01-02"}
        write_dump(d / "a.jsonl", [rec, {"title": "no id"}], array=False)
        m = K.import_dump(d / "a.jsonl", "arxiv", d / "o")
        recs = [json.loads(l) for p in m["parts"] for l in open(d / "o" / p["file"], encoding="utf-8")]
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["abstract_sha256"], hashlib.sha256(b"A long abstract text.").hexdigest())
        self.assertNotIn("A long abstract text", json.dumps(recs))
        self.assertEqual(recs[0]["categories"], ["cs.AI", "cs.CR"])

    def test_unknown_sources_and_share_alike_text_are_not_importable(self):
        d = pathlib.Path(tempfile.mkdtemp())
        write_dump(d / "x.jsonl", [{"id": "x"}], array=False)
        for src in ("wikipedia", "wikileaks", "", None, "WIKIDATA"):
            with self.assertRaises(K.ImportRefused):
                K.import_dump(d / "x.jsonl", src, d / "o")
        self.assertNotIn("wikipedia", K.SOURCES)
        self.assertNotIn("wikileaks", K.SOURCES)
        self.assertTrue(all(not v["taint"] and v["license"] == "CC0-1.0" for v in K.SOURCES.values()))


class Parts(unittest.TestCase):
    def setUp(self):
        self.d = pathlib.Path(tempfile.mkdtemp())
        write_dump(self.d / "big.jsonl", [item("Q%d" % i, "Item number %d" % i, ("Q5",), [("P1", "Q%d" % (i + 1))]) for i in range(1, 201)], array=False)

    def test_parts_roll_over_before_the_limit_and_the_manifest_adds_up(self):
        m = K.import_dump(self.d / "big.jsonl", "wikidata", self.d / "o", max_part_bytes=20_000)
        self.assertGreater(len(m["parts"]), 3)
        for p in m["parts"]:
            self.assertLessEqual(p["bytes"], 20_000)
            self.assertEqual(os.path.getsize(self.d / "o" / p["file"]), p["bytes"])
        total = m["counts"]["nodes"] + m["counts"]["edges"] + m["counts"]["stubs"]
        self.assertEqual(sum(p["records"] for p in m["parts"]), total)
        self.assertEqual(K.verify_parts(m, self.d / "o"), [])
        self.assertTrue((self.d / "o" / "wikidata-MANIFEST.json").exists())

    def test_the_part_size_limit_cannot_be_raised_past_the_hundred_megabyte_rule(self):
        for bad in (10, 100 * 1024 * 1024 + 1, True, "big", None):
            with self.assertRaises(K.ImportRefused):
                K.PartWriter(self.d / "x", "wikidata", bad)
        K.PartWriter(self.d / "x", "wikidata", 100 * 1024 * 1024)

    def test_a_record_over_the_record_cap_is_refused_not_cut(self):
        w = K.PartWriter(self.d / "y", "wikidata", 50_000)
        self.assertFalse(w.write({"kind": "x", "blob": "z" * (K.MAX_RECORD + 10)}))
        self.assertTrue(w.write({"kind": "x"}))

    def test_tampering_with_a_part_the_manifest_or_the_part_list_is_caught(self):
        m = K.import_dump(self.d / "big.jsonl", "wikidata", self.d / "o", max_part_bytes=20_000)
        part = self.d / "o" / m["parts"][1]["file"]
        data = part.read_bytes()
        part.write_bytes(data.replace(b"Item", b"Evil", 1))
        self.assertEqual(len(K.verify_parts(m, self.d / "o")), 1)
        part.write_bytes(data)
        self.assertEqual(K.verify_parts(m, self.d / "o"), [])
        part.unlink()
        self.assertIn("is missing", K.verify_parts(m, self.d / "o")[0])
        part.write_bytes(data)
        bad = copy.deepcopy(m)
        bad["parts"].pop()
        self.assertIn("batch hash", K.verify_parts(bad, self.d / "o")[0])
        bad = copy.deepcopy(m)
        bad["parts"][0]["file"] = "../evil.jsonl"
        self.assertTrue(K.verify_parts(bad, self.d / "o"))
        self.assertTrue(K.verify_parts({}, self.d / "o"))


class Loading(unittest.TestCase):
    def setUp(self):
        self.d = pathlib.Path(tempfile.mkdtemp())
        write_dump(self.d / "w.jsonl", [item("Q%d" % i, "Item %d" % i) for i in range(1, 31)], array=False)
        self.m = K.import_dump(self.d / "w.jsonl", "wikidata", self.d / "o", max_part_bytes=8000)
        self.stored = []

    def loader(self, batch):
        self.stored += batch
        return len(batch)

    def test_the_commitment_names_exactly_this_batch(self):
        req = K.batch_commit_params(self.m)
        self.assertEqual(req["action"], "dkg_import")
        self.assertEqual(req["params"]["batch_sha256"], self.m["batch_sha256"])
        self.assertEqual(req["params"]["nodes"], self.m["counts"]["nodes"])

    def test_nothing_loads_without_an_approving_commitment_for_that_exact_batch(self):
        seen = []

        def check_yes(action, params):
            seen.append((action, params))
            return True
        for check in (lambda a, p: False, lambda a, p: "yes", lambda a, p: 1, lambda a, p: None, lambda a, p: 1 / 0, None):
            with self.assertRaises(K.ImportRefused):
                K.load(self.m, self.d / "o", self.loader, check)
        self.assertEqual(self.stored, [])
        out = K.load(self.m, self.d / "o", self.loader, check_yes, batch_size=7)
        self.assertEqual(seen, [("dkg_import", K.batch_commit_params(self.m)["params"])])
        self.assertEqual((out["sent"], out["stored"]), (len(self.stored), len(self.stored)))
        self.assertEqual(out["sent"], self.m["counts"]["nodes"] + self.m["counts"]["edges"] + self.m["counts"]["stubs"])

    def test_a_tampered_part_stops_the_load_before_anything_is_stored(self):
        part = self.d / "o" / self.m["parts"][0]["file"]
        part.write_bytes(part.read_bytes() + b"{}\n")
        with self.assertRaises(K.ImportRefused):
            K.load(self.m, self.d / "o", self.loader, lambda a, p: True)
        self.assertEqual(self.stored, [])

    def test_the_count_back_catches_a_loader_that_loses_or_overreports_records(self):
        with self.assertRaises(K.ImportRefused):
            K.load(self.m, self.d / "o", lambda batch: len(batch) - 1, lambda a, p: True)
        with self.assertRaises(K.ImportRefused):
            K.load(self.m, self.d / "o", lambda batch: len(batch) + 1, lambda a, p: True)
        for bad in (lambda batch: None, lambda batch: True, lambda batch: -1, lambda batch: "3"):
            with self.assertRaises(K.ImportRefused):
                K.load(self.m, self.d / "o", bad, lambda a, p: True)


if __name__ == "__main__":
    unittest.main()
