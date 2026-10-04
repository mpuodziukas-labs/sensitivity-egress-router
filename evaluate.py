import json
import pathlib

import router

HERE = pathlib.Path(__file__).parent
ORDER = ["secret-key-shape", "private-key", "pii-ssn", "pii-email-phone", "pii-dob", "health-person", "split-window",
         "obfuscated", "base64", "fail-closed", "local-down-refuse"]
PLACEHOLDERS = {"{PK1}": "-----BEGIN RSA ", "{PK2}": "PRIVATE KEY-----", "{XOX}": "xox" + "b-", "{SK}": "sk" + "-", "{SKA}": "sk" + "-ant-", "{GHP}": "ghp" + "_",
                "{PAT}": "github" + "_pat_", "{AKIA}": "AK" + "IA", "{AIZA}": "AI" + "za",
                "{SKDOT}": ".".join("sk" + "-") + ".", "{SKSP}": " ".join("sk" + "-") + " ", "{GHPSP}": " ".join("ghp" + "_") + " "}  # built at run time so no key-shaped literal sits in the repo; every expanded value is synthetic (EXAMPLE filler)


def _boom(messages):
    raise RuntimeError("classifier crashed")


def _slow(messages):
    raise TimeoutError("classifier timed out")


CLASSIFIERS = {"raise": _boom, "timeout": _slow, "empty": lambda m: ("", ""), "none": lambda m: None,
               "unknown": lambda m: ("banana", "x")}


def expand(value):
    if isinstance(value, str):
        value = value.replace("{PK}", "{PK1}{PK2}")
        for k, v in PLACEHOLDERS.items():
            value = value.replace(k, v)
        return value
    return [expand(v) for v in value] if isinstance(value, list) else value


def load(name):
    rows = [json.loads(l) for l in (HERE / name).read_text().splitlines() if l]
    for r in rows:
        r["messages"] = expand(r["messages"])
    return rows


def decide(row):
    return router.route(row["messages"], local_up=row.get("local_up", True), classifier=CLASSIFIERS.get(row.get("classifier")))


def as_expected(row, decision):
    dest = "refuse" if decision["destination"] == "refused" else decision["destination"]
    return dest == row["expect"] and row.get("rule", decision["rule"]) == decision["rule"]


def results():
    out = {}
    for r in load("cases.jsonl"):
        out.setdefault(r["bypass"], []).append(as_expected(r, decide(r)))
    lines = ["| rule class | routed as expected |", "|---|---|"]
    for cls in ORDER:
        lines.append(f"| {cls} | {sum(out[cls])}/{len(out[cls])} |")
    lines.append(f"| control (cloud) | {sum(out['control'])}/{len(out['control'])} |")
    benign = load("benign.jsonl")
    cloud = sum(decide(r)["destination"] == "cloud" for r in benign)
    attacks = [v for k, v in out.items() if k not in ("control", "local-down-refuse")]
    caught = sum(sum(v) for v in attacks)
    total = sum(len(v) for v in attacks)
    lines.append("")
    lines.append(f"sensitive prompts routed local: {caught}/{total}")
    lines.append(f"benign prompts routed cloud: {cloud}/{len(benign)} (over-block {len(benign) - cloud})")
    return "\n".join(lines)


if __name__ == "__main__":
    print(results())
