"""vega_id.py - ONE node id for every layer (the "one plane"), plus a crosswalk from the old ids.

  vega id = 'vn1_' + first 26 hex of sha256( universe | path | kind | label | location | ordinal )
  universe : the repo or graph the node lives in (normalized)
  ordinal  : 0 for the first node with an identical (universe, path, kind, label, location); 1, 2, ... for true duplicates, in sorted order of their
             ORIGINAL local id. Duplicates are never merged: they keep separate vega ids and are flagged collision_group > 1 in the crosswalk.
             Ordinals continue across calls (the count already stored for that tuple), so two batches can never hand the same id to two different nodes.
             For order-independent ids send a whole layer in ONE add_many call; ids from different batching are each unique but not identical.

Separator safety: '|' and '%' inside a field are escaped before joining, so ('a|b','c') and ('a','b|c') are different nodes. Fields without those characters hash exactly
as before, so existing vn1 ids do not change.

The crosswalk (SQLite) maps layer + local id -> vega id. A row is written once; a later row for the same layer + local id with DIFFERENT content is REPORTED as a conflict
(never silently ignored, never overwritten). Nothing is truncated: the local id is stored whole.

  with Crosswalk(path) as cw:  cw.add_many(layer, rows) -> {"rows","added","unchanged","conflicts":[...]} ; cw.lookup(layer, local_id) ; cw.stats()"""
import hashlib
import os
import sqlite3

PREFIX = "vn1_"
MAX_FIELD = 100_000


class IdRefused(ValueError):
    pass


def _n(s):
    s = "" if s is None else str(s)
    if len(s) > MAX_FIELD:
        raise IdRefused(f"id field is {len(s)} characters, over {MAX_FIELD}")
    return s.strip().replace("\\", "/").lower().replace("%", "%25").replace("|", "%7C")


def vega_id(universe, path, kind, label, location, ordinal=0):
    if isinstance(ordinal, bool) or not isinstance(ordinal, int) or ordinal < 0:
        raise IdRefused("ordinal is a whole number, 0 or more")
    base = "|".join([_n(universe), _n(path), _n(kind), _n(label), _n(location), str(ordinal)])
    return PREFIX + hashlib.sha256(base.encode("utf-8")).hexdigest()[:26]


def _base_key(tup):
    return hashlib.sha256("|".join(tup).encode("utf-8")).hexdigest()


class Crosswalk:
    def __init__(self, path):
        self.path = path
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.con = sqlite3.connect(path, timeout=30)
        self.con.execute("pragma journal_mode=wal")
        self.con.execute("""create table if not exists crosswalk(
            layer text not null, local_id text not null, vega_id text not null, universe text,
            collision_group integer not null default 1, base_key text, primary key(layer, local_id))""")
        cols = {r[1] for r in self.con.execute("pragma table_info(crosswalk)")}
        if "base_key" not in cols:
            self.con.execute("alter table crosswalk add column base_key text")
        self.con.execute("create index if not exists ix_vega on crosswalk(vega_id)")
        self.con.execute("create index if not exists ix_base on crosswalk(layer, base_key)")
        self.con.execute("create unique index if not exists ux_layer_vega on crosswalk(layer, vega_id)")
        self.con.commit()

    def close(self):
        self.con.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    def add_many(self, layer, rows):
        """rows: iterable of dicts with local_id, universe, path, kind, label, location. Returns a report; conflicts are listed, never hidden."""
        if not isinstance(layer, str) or not layer:
            raise IdRefused("layer must be text")
        rows = list(rows)
        for r in rows:
            if not isinstance(r, dict) or "local_id" not in r:
                raise IdRefused("every row is an object with a local_id")
        rows.sort(key=lambda r: str(r["local_id"]))
        stored = {}
        for lid in {str(r["local_id"]) for r in rows}:
            got = self.con.execute("select vega_id, base_key from crosswalk where layer=? and local_id=?", (layer, lid)).fetchone()
            if got:
                stored[lid] = got
        offset = {}
        new, unchanged, conflicts = [], 0, []
        counts = {}
        for r in rows:
            tup = tuple(_n(r.get(k)) for k in ("universe", "path", "kind", "label", "location"))
            bk = _base_key(tup)
            lid = str(r["local_id"])
            if lid in stored:
                if stored[lid][1] == bk:
                    unchanged += 1
                else:
                    conflicts.append({"local_id": lid, "stored_vega_id": stored[lid][0], "reason": "the stored row describes a different node; the original id is kept"})
                continue
            if bk not in offset:
                offset[bk] = self.con.execute("select count(*) from crosswalk where layer=? and base_key=?", (layer, bk)).fetchone()[0]
            o = offset[bk]
            offset[bk] = o + 1
            counts[bk] = counts.get(bk, 0) + 1
            new.append((layer, lid, vega_id(r.get("universe"), r.get("path"), r.get("kind"), r.get("label"), r.get("location"), o), r.get("universe"), bk))
        try:
            self.con.executemany("insert into crosswalk(layer, local_id, vega_id, universe, collision_group, base_key) values (?,?,?,?,1,?)", new)
            groups = {bk for bk in counts}
            for bk in groups:
                n = self.con.execute("select count(*) from crosswalk where layer=? and base_key=?", (layer, bk)).fetchone()[0]
                self.con.execute("update crosswalk set collision_group=? where layer=? and base_key=?", (n, layer, bk))
            self.con.commit()
        except sqlite3.Error:
            self.con.rollback()
            raise
        return {"rows": len(rows), "added": len(new), "unchanged": unchanged, "conflicts": conflicts}

    def lookup(self, layer, local_id):
        r = self.con.execute("select vega_id from crosswalk where layer=? and local_id=?", (layer, str(local_id))).fetchone()
        return r[0] if r else None

    def stats(self):
        rows = self.con.execute("select layer, count(*), sum(collision_group > 1), count(distinct vega_id) from crosswalk group by layer").fetchall()
        return [{"layer": l, "nodes": n, "in_collision_groups": c or 0, "distinct_vega_ids": d} for l, n, c, d in rows]
