import json
import pathlib
import re
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))
import evaluate
import router

CASES = evaluate.load("cases.jsonl")
BENIGN = evaluate.load("benign.jsonl")


@pytest.mark.parametrize("row", CASES, ids=lambda r: r["id"])
def test_planted_case_routes_as_labeled(row):
    decision = evaluate.decide(row)
    assert evaluate.as_expected(row, decision), (row["expect"], decision)


@pytest.mark.parametrize("row", BENIGN, ids=lambda r: r["id"])
def test_benign_prompt_routes_cloud_except_pinned_overblocks(row):
    want = "local" if row.get("known_overblock") else "cloud"
    assert evaluate.decide(row)["destination"] == want


def test_every_fixture_is_labeled_synthetic():
    assert CASES and BENIGN and all(r.get("synthetic") is True for r in CASES + BENIGN)


def test_sensitive_with_local_down_is_exit_3_never_cloud():
    d = router.route(["ssn 123-45-6789"], local_up=False)
    assert d["destination"] == "refused" and d["exit"] == 3


@pytest.mark.parametrize("row", CASES, ids=lambda r: r["id"])
def test_log_line_holds_class_destination_rule_only(row):
    line = router.log_line(evaluate.decide(row))
    assert list(json.loads(line)) == ["class", "destination", "rule"]
    assert json.loads(line)["rule"].split("+")[0] in router.KNOWN_RULES
    msgs = row["messages"] if isinstance(row["messages"], list) else []
    assert not any(m and m in line for m in msgs if isinstance(m, str))
    assert "EXAMPLE" not in line


def test_cost_decides_only_among_allowed_destinations(monkeypatch):
    monkeypatch.setitem(router.DESTINATIONS, "cloud", 0.0)
    monkeypatch.setitem(router.DESTINATIONS, "local", 9.0)
    assert router.route(evaluate.expand(["key {SK}EXAMPLE0123456789ABCDEF"]))["destination"] == "local"
    assert router.route(["what is a mutex?"])["destination"] == "cloud"
    monkeypatch.setitem(router.DESTINATIONS, "local", 0.0)
    monkeypatch.setitem(router.DESTINATIONS, "cloud", 9.0)
    assert router.route(["what is a mutex?"])["destination"] == "local"


def run_cli(stdin, *args):
    return subprocess.run([sys.executable, str(ROOT / "router.py"), *args], input=stdin, capture_output=True, text=True, timeout=30)


def test_cli_routes_and_logs():
    p = run_cli(json.dumps(["what is a mutex?"]))
    assert p.returncode == 0 and json.loads(p.stdout) == {"class": "clean", "destination": "cloud", "rule": "clean"}


def test_cli_exit_3_when_local_down_and_sensitive():
    p = run_cli(json.dumps(["ssn 123-45-6789"]), "--local-down")
    assert p.returncode == 3 and json.loads(p.stdout)["destination"] == "refused"


@pytest.mark.parametrize("stdin", ["not json", "", "{}", "[]", "[1]"])
def test_cli_bad_input_is_local_never_cloud(stdin):
    assert json.loads(run_cli(stdin).stdout)["destination"] == "local"
    assert run_cli(stdin, "--local-down").returncode == 3


def test_readme_matches_output():
    readme = (ROOT / "README.md").read_text()
    assert evaluate.results() in readme, "README results drifted from evaluate.py"


def test_no_secret_header_or_real_looking_key_in_repo():
    for f in ROOT.rglob("*"):
        if f.is_file() and ".git" not in f.parts and f.suffix in {".py", ".jsonl", ".md", ".txt", ".yml"}:
            text = f.read_text()
            assert not re.search(r"BEGIN [A-Z ]*PRIVATE KEY", text), f
            assert all("EXAMPLE" in m.group() for m in re.finditer(r"sk-[A-Za-z0-9]{20}", text)), f


def mutant(monkeypatch, name, value):
    real = evaluate.results()
    monkeypatch.setattr(router, name, value)
    assert evaluate.results() != real, f"mutant {name} was not caught"


def test_mutant_cost_first_ignores_class(monkeypatch):
    real = evaluate.results()
    monkeypatch.setattr(router, "ALLOWED", {k: ("local", "cloud") for k in router.ALLOWED})
    assert evaluate.results() != real


def test_mutant_unclassified_goes_cloud(monkeypatch):
    real = evaluate.results()
    monkeypatch.setitem(router.ALLOWED, "unclassified", ("cloud",))
    assert evaluate.results() != real


def test_mutant_failover_to_cloud_when_local_down(monkeypatch):
    mutant(monkeypatch, "FAILOVER", True)


def test_mutant_only_last_message_scanned(monkeypatch):
    mutant(monkeypatch, "WINDOW", 1)


def test_mutant_obfuscation_not_scanned(monkeypatch):
    mutant(monkeypatch, "scan_spaced", lambda t: None)


def test_mutant_base64_not_decoded(monkeypatch):
    mutant(monkeypatch, "decode_b64", lambda t: [])


def test_mutant_key_shapes_removed(monkeypatch):
    mutant(monkeypatch, "SECRET_PLAIN", [])


def test_mutant_private_key_rule_removed(monkeypatch):
    mutant(monkeypatch, "PRIVATE_KEY", re.compile("(?!)"))


def test_mutant_ssn_rule_removed(monkeypatch):
    mutant(monkeypatch, "SSN", re.compile("(?!)"))


def test_mutant_phone_rule_removed(monkeypatch):
    mutant(monkeypatch, "PHONE", re.compile("(?!)"))


def test_mutant_dob_rule_removed(monkeypatch):
    mutant(monkeypatch, "DOB", re.compile("(?!)"))


def test_mutant_health_rule_removed(monkeypatch):
    mutant(monkeypatch, "HEALTH", re.compile("(?!)"))


def test_mutant_classifier_failure_fails_open(monkeypatch):
    real = evaluate.results()
    orig = router.route

    def loose(messages, local_up=True, classifier=None):
        try:
            if classifier:
                classifier(messages)
        except Exception:
            return {"class": "clean", "destination": "cloud", "rule": "clean", "exit": 0}
        return orig(messages, local_up, classifier)

    monkeypatch.setattr(router, "route", loose)
    assert evaluate.results() != real


def test_mutant_log_line_holding_text_is_caught(monkeypatch):
    row = next(r for r in CASES if r["id"] == "k-openai")
    monkeypatch.setattr(router, "log_line", lambda d: json.dumps({**d, "text": row["messages"][0]}))
    line = router.log_line(evaluate.decide(row))
    assert row["messages"][0] in line
    assert list(json.loads(line)) != ["class", "destination", "rule"]
