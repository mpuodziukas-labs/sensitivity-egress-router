import base64
import json
import pathlib
import re
import sys
import unicodedata
from urllib.parse import quote

import pytest

ROOT = pathlib.Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))
import evaluate
import router

WJ = chr(0x2060)  # word joiner: not in the old separator set
BIDI = [chr(0x202E), chr(0x00AD), chr(0x2066)]  # right-to-left override, soft hyphen, isolate


def _apply(name, msgs):
    one = "\n".join(msgs)
    if name == "wj":
        return ["".join(c + WJ if i % 3 == 1 else c for i, c in enumerate(one))]
    if name == "bidi":
        return ["".join(c + BIDI[i % 3] if i % 4 == 2 else c for i, c in enumerate(one))]
    if name == "fullwidth":
        return ["".join(chr(ord(c) + 0xFEE0) if "!" <= c <= "~" else c for c in one)]
    if name == "case":
        return ["".join(c.swapcase() if i % 2 == 0 else c for i, c in enumerate(one))]
    if name == "lower":
        return [one.lower()]
    if name == "hex":
        return ["hex: " + one.encode().hex()]
    if name == "b64":
        return ["payload=" + base64.b64encode(one.encode()).decode()]
    if name == "url":
        return [quote(one, safe="")]
    if name == "split2":
        return [one[: len(one) // 2], one[len(one) // 2:]]
    raise ValueError(name)


def load_v2():
    rows = []
    for line in (ROOT / "cases_v2.jsonl").read_text().splitlines():
        if not line:
            continue
        r = json.loads(line)
        msgs = evaluate.expand(r["messages"])
        msgs = [m.replace("{LONGHEX}", "61" * 5000).replace("{LONGB64}", "QUJD" * 2500) for m in msgs]
        for step in r.get("transform", []):
            msgs = _apply(step, msgs)
        r["messages"] = msgs
        rows.append(r)
    return rows


V2 = load_v2()


def routed(row):
    return evaluate.as_expected(row, router.route(row["messages"]))


def table():
    return {r["id"]: router.route(r["messages"]) for r in V2}


def test_v2_fixtures_are_synthetic_and_nonempty():
    assert len(V2) >= 30 and all(r.get("synthetic") is True for r in V2)
    assert {r["bypass"] for r in V2} >= {"v2-invisible", "v2-nfkc", "v2-case", "v2-hex", "v2-b64", "v2-url", "v2-overlong", "v2-control"}


@pytest.mark.parametrize("row", V2, ids=lambda r: r["id"])
def test_v2_case_routes_as_labeled(row):
    d = router.route(row["messages"])
    assert evaluate.as_expected(row, d), (row["expect"], d)


def test_v2_overlong_run_is_unclassified_local():
    d = router.route(["blob=" + "61" * 5000])
    assert (d["class"], d["destination"], d["rule"]) == ("unclassified", "local", "unclassified")
    assert router.route(["blob=" + "61" * 5000], local_up=False)["exit"] == 3


def test_v2_decoded_hit_logs_no_text():
    row = next(r for r in V2 if r["id"] == "hex-key")
    line = router.log_line(router.route(row["messages"]))
    assert list(json.loads(line)) == ["class", "destination", "rule"] and "EXAMPLE" not in line


def test_v2_no_new_overblock_on_benign_corpus():
    benign = evaluate.load("benign.jsonl")
    over = sum(router.route(r["messages"])["destination"] != "cloud" for r in benign)
    assert over == 4, over  # the four pinned rows; any other change is a decision, not a drift


# mutants: one per canonicalization step. Each must turn the v2 table.
def mut(monkeypatch, name, value):
    real = table()
    monkeypatch.setattr(router, name, value)
    assert table() != real, f"mutant {name} was not caught"


def test_mutant_invisible_strip_removed(monkeypatch):
    mut(monkeypatch, "strip_invisible", lambda t: t)


def test_mutant_nfkc_removed(monkeypatch):
    mut(monkeypatch, "nfkc", lambda t: t)


def test_mutant_casefold_scan_removed(monkeypatch):
    mut(monkeypatch, "scan_folded", lambda t: None)


def test_mutant_hex_decode_removed(monkeypatch):
    mut(monkeypatch, "decode_hex", lambda t: [])


def test_mutant_url_decode_removed(monkeypatch):
    mut(monkeypatch, "decode_url", lambda t: [])


def test_mutant_decoded_views_not_canonicalized(monkeypatch):
    mut(monkeypatch, "canon_decoded", lambda t: t)


def test_mutant_overlong_run_not_failed_closed(monkeypatch):
    mut(monkeypatch, "MAX_RUN", 10 ** 9)
