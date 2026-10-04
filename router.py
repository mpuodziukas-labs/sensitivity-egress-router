"""Classify a prompt first, then pick a destination. Cost only breaks ties among allowed destinations."""
import base64
import json
import re
import sys

DESTINATIONS = {"local": 0.50, "cloud": 0.10}  # synthetic cost per 1k tokens; local is dearer on purpose
ALLOWED = {"clean": ("local", "cloud"), "secret": ("local",), "pii": ("local",), "health": ("local",), "unclassified": ("local",)}
FAILOVER = False  # sensitive + local down: never fall over to cloud
WINDOW = None  # None = scan every message that would be sent; N = last N only

SEP = r"[\s.​-‍﻿]*"  # spacing, dots and zero-width characters an attacker inserts
SECRET_SPECS = [  # (rule, prefix, body character class, minimum body length)
    ("secret-openai-shape", "sk-", "[A-Za-z0-9]", 20),
    ("secret-anthropic-shape", "sk-ant-", "[A-Za-z0-9_-]", 20),
    ("secret-github-token", "ghp_", "[A-Za-z0-9]", 20),
    ("secret-github-pat", "github_pat_", "[A-Za-z0-9_]", 20),
    ("secret-aws-key-id", "AKIA", "[0-9A-Z]", 16),
    ("secret-google-key", "AIza", "[0-9A-Za-z_-]", 30),
    ("secret-slack-token", "xox" + "b-", "[A-Za-z0-9-]", 10),
]
PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY")


def _plain(prefix, body, n):
    return re.compile(r"(?<![A-Za-z0-9])" + re.escape(prefix) + body + "{%d,}" % n)


def _spaced(prefix, body, n):
    head = SEP.join(re.escape(c) for c in prefix) + SEP
    return re.compile(r"(?<![A-Za-z0-9])" + head + "(?:" + body + SEP + "){%d,}" % n)


SECRET_PLAIN = [(r, _plain(p, b, n)) for r, p, b, n in SECRET_SPECS]
SECRET_SPACED = [(r + "+obfuscated", _spaced(p, b, n)) for r, p, b, n in SECRET_SPECS]
SSN = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
SSN_SPACED = re.compile(r"(?<!\d)\d%s\d%s\d%s-%s\d%s\d%s-%s\d%s\d%s\d%s\d(?!\d)" % ((SEP,) * 10))
EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
PHONE = re.compile(r"(?<!\d)(?:\+?1[ .-]?)?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}(?!\d)")
DOB = re.compile(r"\b(?:dob|d\.o\.b\.|date of birth|born(?: on)?)(?: (?:as|is|was))?\W{0,3}(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}-\d{2}-\d{2}"
                 r"|(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]* \d{1,2},? \d{4})", re.I)
HEALTH = re.compile(r"\b(?:diagnos\w*|prescri\w*|medications?|cancer|diabet\w*|hiv|depress\w*|adhd|chemotherap\w*|biops\w*"
                    r"|oncolog\w*|hypertension|insulin|lab results?)\b", re.I)
PERSON = re.compile(r"\b(?:Patient|Mr|Mrs|Ms)\.? [A-Z][a-z]+\b|\bMRN\b"
                    r"|\b[Ii] (?:was|am|have been|got) (?:diagnosed|prescribed|treated)\b"
                    r"|\b[Mm]y (?:mother|father|wife|husband|son|daughter|patient|doctor|diagnosis|therapist)\b")
B64 = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
KNOWN_RULES = {r for r, *_ in SECRET_SPECS} | {
    "private-key", "pii-ssn", "pii-email-phone", "pii-dob", "health-person", "clean", "unclassified"}


def scan_plain(text):
    for rule, rx in SECRET_PLAIN:
        if rx.search(text):
            return "secret", rule
    if PRIVATE_KEY.search(text):
        return "secret", "private-key"
    if SSN.search(text):
        return "pii", "pii-ssn"
    if EMAIL.search(text) and PHONE.search(text):
        return "pii", "pii-email-phone"
    if DOB.search(text):
        return "pii", "pii-dob"
    if HEALTH.search(text) and PERSON.search(text):
        return "health", "health-person"
    return None


def scan_spaced(text):
    for rule, rx in SECRET_SPACED:
        if rx.search(text):
            return "secret", rule
    if SSN_SPACED.search(text):
        return "pii", "pii-ssn+obfuscated"
    return None


def decode_b64(text):
    for m in B64.findall(text):
        try:
            raw = base64.b64decode(m.replace("-", "+").replace("_", "/") + "=" * (-len(m) % 4))
            s = raw.decode("utf-8")
        except ValueError:
            continue
        if s and sum(c.isprintable() for c in s) / len(s) >= 0.9:
            yield s


def classify(messages):
    """Return (class, rule). Scans the joined window, so a secret split over turns is one string."""
    window = messages[-WINDOW:] if WINDOW else messages
    texts = ("\n".join(window), "".join(window))
    for scan in (scan_plain, scan_spaced):
        for text in texts:
            hit = scan(text)
            if hit:
                return hit
    for text in texts:
        for decoded in decode_b64(text):
            hit = scan_plain(decoded)
            if hit:
                return hit[0], hit[1] + "+base64"
    return "clean", "clean"


def route(messages, local_up=True, classifier=None):
    """Decision dict: class, destination (local, cloud or refused), rule, exit (0 or 3)."""
    try:
        if not isinstance(messages, list) or not messages or not all(isinstance(m, str) and m.strip() for m in messages):
            raise ValueError("unusable input")
        cls, rule = (classifier or classify)(messages)
        if cls not in ALLOWED or not rule:
            raise ValueError("classifier gave no usable class")
    except Exception:  # error, timeout, empty result, odd input: never cloud by default
        cls, rule = "unclassified", "unclassified"
    options = [d for d in ALLOWED[cls] if d != "local" or local_up]
    if not options and FAILOVER:
        options = [d for d in DESTINATIONS if d != "local" or local_up]
    if not options:
        return {"class": cls, "destination": "refused", "rule": rule, "exit": 3}
    return {"class": cls, "destination": min(options, key=DESTINATIONS.get), "rule": rule, "exit": 0}


def log_line(decision):
    """One line per decision. Class, destination and rule id only; never any prompt text."""
    return json.dumps({k: decision[k] for k in ("class", "destination", "rule")}, sort_keys=True)


def main(argv):
    try:
        messages = json.loads(sys.stdin.read())
    except ValueError:
        messages = None
    decision = route(messages, local_up="--local-down" not in argv)
    print(log_line(decision))
    return decision["exit"]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
