"""candidate_verify.py - verify a library candidate against GRAPH FACTS (cards), no model, no execution.

Used by reasoning_pipeline stage s10b (deps['verify_candidate']). Criteria (each a fact read from the repo card; unknown stays unknown):
  c1 license class is PERMISSIVE (adoptable)       c2 audit status COMPLETE        c3 test evidence (the card's test_share_of_code score >= 0.05; the score is already a Wilson lower bound)
  c4 the node is connected (degree >= 2)           c5 edges mostly extracted not inferred (card score >= 0.5)
score = fraction of criteria passed (+ up to 0.1 for degree). passes = all five. A candidate that is a combination hypothesis is verified through BOTH of its parents; the weaker
parent decides, and the combination itself never passes (it is a hypothesis until a contained run). HONEST LIMIT: passing means the graph facts look sound, NOT that the code works.
Nothing is executed. A card is only as true as the process that built it: this reads cards, it does not re-derive them.

Safety: a repo name must be one plain path component (it names a card file); a card that is missing, too big, not JSON or not an object is 'no card: nothing verified'; non-numeric
scores count as not passed instead of crashing; the card cache is keyed by (cards folder, repo) and by the file's modification time, so a changed card or another folder is never served stale."""
import json
import os
import threading

from vega_dkg import safe_paths as sp

MAX_CARD_LINE = 8 * 1024 * 1024
MAX_CACHE = 256                       # repo cards held in memory; the oldest is dropped first
_cache = {}
_cache_lock = threading.Lock()


def _num(x):
    return x if isinstance(x, (int, float)) and not isinstance(x, bool) and x == x else 0


def repo_facts(repo, cards):
    """The repo card (first line of <cards>/<repo>.jsonl) or None."""
    sp.safe_name(repo)
    p = sp.contained(cards, repo + ".jsonl")
    try:
        stamp = (os.path.getmtime(p), os.path.getsize(p))
    except OSError:
        return None
    key = (os.path.realpath(cards), repo)
    with _cache_lock:
        hit = _cache.get(key)
    if hit and hit[0] == stamp:
        return hit[1]
    try:
        with open(p, "rb") as fh:
            line = fh.readline(MAX_CARD_LINE + 1)
        if len(line) > MAX_CARD_LINE:
            raise ValueError("card line too long")
        first = json.loads(line.decode("utf-8"))
        first = first if isinstance(first, dict) and first.get("kind") == "repo_node" else None
    except (OSError, ValueError):
        first = None
    with _cache_lock:
        _cache.pop(key, None)
        _cache[key] = (stamp, first)
        while len(_cache) > MAX_CACHE:
            _cache.pop(next(iter(_cache)))
    return first


def verify_node(repo, degree=None, cards=None):
    if cards is None:
        raise ValueError("cards folder is required")
    f = repo_facts(repo, cards)
    if f is None:
        return {"passes": False, "score": 0.0, "criteria": {}, "why": "no usable card for repo %s: nothing verified" % repo}
    sc = f.get("score_dimensions")
    sc = sc if isinstance(sc, dict) else {}
    if degree is not None and (isinstance(degree, bool) or not isinstance(degree, int) or degree < 0):
        degree = None
    crit = {"c1_permissive": f.get("license_class") == "PERMISSIVE", "c2_audit_complete": f.get("audit_status") == "COMPLETE",
            "c3_test_evidence": _num(sc.get("test_share_of_code")) >= 0.05,
            "c4_connected": None if degree is None else degree >= 2,           # unknown is counted as not passed
            "c5_edges_extracted": _num(sc.get("graph_edges_extracted_not_inferred")) >= 0.5}
    passed = sum(1 for v in crit.values() if v)
    score = round(passed / 5 + (0.1 * min(degree, 10) / 10 if degree else 0.0), 3)
    failed = [k for k, v in crit.items() if not v]
    return {"passes": passed == 5, "score": score, "criteria": crit, "license_class": f.get("license_class"),
            "why": ("all five graph checks passed" if passed == 5 else "failed or unknown: " + ", ".join(failed))}


def verify_candidate(c, cards):
    """c: a library fit {'repo',...[,'degree']}, or a combination hypothesis with weak_symbol / strong_symbol, or a locked workflow (cannot be graph-verified)."""
    if not isinstance(c, dict):
        return {"passes": False, "score": 0.0, "why": "unrecognized candidate shape"}
    try:
        if isinstance(c.get("weak_symbol"), dict) and isinstance(c.get("strong_symbol"), dict):
            a = verify_node(c["weak_symbol"].get("repo"), None, cards)
            b = verify_node(c["strong_symbol"].get("repo"), None, cards)
            worst = min((a, b), key=lambda v: v["score"])
            return {"passes": False, "score": worst["score"], "why": "combination is a hypothesis: needs a contained run; parents: weak=%s strong=%s" % (a["why"], b["why"]),
                    "parents": {"weak": a, "strong": b}, "criteria": worst.get("criteria", {})}
        if c.get("kind") == "locked_workflow":
            return {"passes": False, "score": 0.0, "why": "a locked workflow proves a past result reproduced, not that it is still the best: verify against the current goal"}
        if "repo" in c:
            return verify_node(c["repo"], c.get("degree"), cards)
    except sp.PathRefused as exc:
        return {"passes": False, "score": 0.0, "why": "candidate names an unsafe repo: %s" % exc}
    return {"passes": False, "score": 0.0, "why": "unrecognized candidate shape"}
