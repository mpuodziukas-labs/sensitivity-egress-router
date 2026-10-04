"""Hostile review 2026-10-04: one test per finding R1-R18. Every key is synthetic and built at run time."""
import base64
import json
import pathlib
import re
import sys
import time

import pytest

ROOT = pathlib.Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))
import router

K = "s" + "k-" + "Ab3Xy9" * 4  # synthetic key shape, built at run time


def b64(x):
    return base64.b64encode(x).decode()


def wrap(s, n):
    return "\n".join(s[i:i + n] for i in range(0, len(s), n))


KB = K.encode()
SECRET_ROWS = {
    "R1": "note " + b64(b"key " + KB + b"\xff"),
    "R2": "note " + (b"key " + KB + b"\xff").hex(),
    "R3": "note ff" + (b"key " + KB).hex(),
    "R4a": "token" + b64(b"key " + KB),
    "R4b": "x" + b64(b"key " + KB),
    "R5": wrap(b64(b"p" * 45 + b" key " + KB + b" end"), 76),
    "R6": wrap((b"p" * 20 + b" key " + KB).hex(), 64),
    "R7": "note " + b64(("key " + K).encode("utf-16-le")),
    "R8": "note " + ("key " + K).encode("utf-16-le").hex(),
    "R9": "note " + b64(b"key " + KB + b"\x01" * 6),
    "R10": "s️k-" + "Ab3Xy9" * 4,
    "R11": "s͏k-" + "Ab3Xy9" * 4,
    "R12": "s\x00k\x00-" + "Ab3Xy9" * 4,
    "R13": '{"note":"\\u0073k-' + "Ab3Xy9" * 4 + '"}',
    "R14": '{"a":"sk-Ab3Xy9","b":"' + "Ab3Xy9" * 3 + '"}',
}
HEALTH_ROWS = {
    "R15a": "Mrs. Zoë was diagnosed with cancer",
    "R15b": "Mr. José has diabetes",
    "R16": "see Mr.%20Ren%C3%A9 diagnosed with cancer",
    "R17": "Mr. O’Brien has diabetes",
}


@pytest.mark.parametrize("rid", sorted(SECRET_ROWS))
def test_secret_view_not_dropped(rid):
    d = router.route([SECRET_ROWS[rid]])
    assert (d["class"], d["destination"]) == ("secret", "local"), (rid, d)


@pytest.mark.parametrize("rid", sorted(HEALTH_ROWS))
def test_unicode_person_health(rid):
    d = router.route([HEALTH_ROWS[rid]])
    assert (d["class"], d["destination"]) == ("health", "local"), (rid, d)


def test_R18_email_regex_bounded():
    for t in ("a." * 32000, "a" * 64000, "a.b" * 21000):
        t0 = time.time()
        router.route([t])
        assert time.time() - t0 < 1.0, len(t)
    t0 = time.time()
    router.route(["a." * 32000 + "@x"])
    assert time.time() - t0 < 1.0


def test_R18_email_still_detected():
    d = router.route(["mail jane.doe+x@example.com or call 555-123-4567"])
    assert d["class"] == "pii"


def test_dense_encoded_text_is_linear():
    t0 = time.time()
    router.route([("A" * 4000 + " ") * 16])
    assert time.time() - t0 < 10


def _hits():
    ok = [router.route([t])["destination"] == "local" for t in list(SECRET_ROWS.values()) + list(HEALTH_ROWS.values())]
    return sum(ok)


def test_all_hostile_rows_local_baseline():
    assert _hits() == len(SECRET_ROWS) + len(HEALTH_ROWS)


@pytest.mark.parametrize("name,value", [
    ("decode_json", lambda t: []),
    ("decode_b64", lambda t: []),
    ("decode_hex", lambda t: []),
    ("strip_invisible", lambda t: t),
    ("_text_views", lambda raw: iter([raw.decode("utf-8", errors="ignore")[:0]])),
])
def test_mutant_hostile_fix_removed(monkeypatch, name, value):
    real = _hits()
    monkeypatch.setattr(router, name, value)
    assert _hits() < real, f"mutant {name} not caught"


def test_mutant_person_ascii_only(monkeypatch):
    real = _hits()
    monkeypatch.setattr(router, "PERSON", re.compile(r"\b(?:Patient|Mr|Mrs|Ms)\.? [A-Z][a-z]+\b"))
    monkeypatch.setattr(router, "PERSON_FOLD", re.compile(r"\b(?:Patient|Mr|Mrs|Ms)\.? [A-Z][a-z]+\b"))
    assert _hits() < real
