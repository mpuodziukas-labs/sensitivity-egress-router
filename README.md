# sensitivity-egress-router

Proves: a prompt carrying a planted key, SSN or patient note never reaches a cloud destination, even when the cloud is cheaper. Verify in 60s: bash run.sh

A team routes prompts to cheap cloud models, and a router that picks by cost first sends one resume, key or patient note to a vendor with no way to take it back. This router classifies the prompt first and picks a destination second. Cost decides only among the destinations the class allows.

## Run it (60s)

```
python3 -m pip install pytest
bash run.sh
```

`bash run.sh` runs `python3 evaluate.py` and then `python3 -m pytest -q`. It finishes in about a second. `python3 evaluate.py` printed:

```
| rule class | routed as expected |
|---|---|
| secret-key-shape | 7/7 |
| private-key | 2/2 |
| pii-ssn | 2/2 |
| pii-email-phone | 2/2 |
| pii-dob | 3/3 |
| health-person | 4/4 |
| split-window | 5/5 |
| obfuscated | 5/5 |
| base64 | 4/4 |
| fail-closed | 11/11 |
| local-down-refuse | 5/5 |
| control (cloud) | 5/5 |

sensitive prompts routed local: 45/45
benign prompts routed cloud: 43/47 (over-block 4)
```

`python3 -m pytest -q` prints a passed count with no failures. A decision looks like this on the command line, with local reported as down:

```
echo '["ssn 123-45-6789"]' | python3 router.py --local-down    # prints one log line, exit 3
echo '["what is a mutex?"]' | python3 router.py                # prints one log line, exit 0
```

## What each planted case proves

A request is a list of chat messages. The router returns a class (secret, pii, health, clean or unclassified), a destination (local, cloud or refused) and a rule id. Every row of cases.jsonl carries the destination and the rule id it must get. Every value in cases.jsonl and benign.jsonl is synthetic and labeled `"synthetic": true`. Key shapes carry the word EXAMPLE, and the private key header is assembled at run time.

- secret-key-shape (k-openai, k-anthropic, k-ghp, k-pat, k-aws, k-google, k-slack): seven well-known key prefixes with a long body go local.
- private-key (pk-block, pk-ec): a private key header goes local.
- pii-ssn, pii-email-phone, pii-dob: an SSN, an email together with a phone number, and a date of birth go local. An email alone is not blocked (c-email-only).
- health-person (h-patient, h-mr, h-first, h-family): a health term together with a person goes local. A health term alone (what are the symptoms of diabetes) goes to cloud.
- split-window (split-key-2, split-key-3, split-ssn, split-pk, split-late-turn): the scan runs on every message that would be sent, joined without a gap, so a key split over two or three turns is one string, and a key sent early stays caught when later turns look clean.
- obfuscated (obf-spaced, obf-dotted, obf-zero-width, obf-ssn, obf-ghp): spaces, dots and zero-width characters between the characters of a key or SSN do not hide it.
- base64 (b64-key, b64-ssn, b64-ghp, b64-split): a base64 run that decodes to printable text is scanned again, including when the run is split over two turns.
- fail-closed (fc-raise, fc-timeout, fc-empty, fc-none, fc-unknown and six malformed inputs): a classifier that raises, times out, returns nothing or returns an unknown class, and any input that is not a non-empty list of non-blank strings, routes local with rule `unclassified`.
- local-down-refuse (ld-secret, ld-pii, ld-health, ld-unclassified, ld-b64): with local down and a sensitive or unclassified prompt, the router refuses with exit 3 and never fails over to cloud. A clean prompt with local down still goes to cloud (c-down).
- control (c-code, c-question, c-email-only, c-hash, c-down): ordinary prompts go to cloud with rule `clean`.

The send log holds `{"class", "destination", "rule"}` and nothing else. A test checks that no message text and no fixture marker appears in any log line.

The tests also break the router on purpose and require the table to change each time: cost decides before class, unclassified allowed to cloud, failover to cloud when local is down, only the last message scanned, obfuscation not scanned, base64 not decoded, key shapes removed, private key rule removed, SSN rule removed, phone rule removed, date of birth rule removed, health rule removed, a classifier failure treated as clean, and a log line that carries the prompt text.

## Benign corpus and over-block

benign.jsonl holds 47 ordinary prompts: code, questions, a README, general health questions, hashes, a UUID, camel-case identifiers and look-alike words such as scikit-learn. 43 route to cloud. 4 route local although nothing sensitive is in them (rows x00 to x03, marked `known_overblock`): a support footer with an email and a phone number, a database table named Patient Visits, a lesson plan that names Mr. Rogers and insulin, and an intake form template. Over-block count: 4 of 47. The tests pin those four as local, so a change in either direction shows up. I wrote the corpus and the patterns myself, so a zero on the first 43 says the patterns do not trip on that style of text, not that they would on yours.

## v2 decode

A Monte Carlo fuzz of v1 (guard-fuzz-montecarlo, seed mcfuzz-v1-20261004) found 0.508 [0.487, 0.530] of mutated sensitive prompts routed to cloud. Solo bypass rates: hex_wrap 1.000, case_change 0.857, zero_width 0.735. v2 classifies the raw prompt first, exactly as v1 did, and then these views of it. Any sensitive view routes local.

1. Strip every Unicode format character (zero-width, word joiner, bidi controls, soft hyphen), NFKC normalize, strip again.
2. Scan that view, then scan it again with case-insensitive key shapes, key header and person markers.
3. Decode one level of hex (16 or more hex characters), URL percent-encoding and base64. Keep a decoded string only if it is at least 90% text. Invisible format characters count as text. Run every decoded string through steps 1 and 2.
4. An unbroken encoded run of 4096 characters or more is not decoded. It routes as `unclassified`, which is local, and with local down it is refused.

Rule ids from v2 views carry a suffix: `+canon`, `+hex`, `+url` or `+base64`.

Tests: `cases_v2.jsonl` holds 36 synthetic fixtures in eight classes (invisible, nfkc, case, hex, base64, url, overlong, and a control class that must stay cloud). They were written first. The failing run is in RED-RUN-V2.txt (35 failed, 13 passed of 48, against v1; that run had 37 fixtures, and one that v1 already routed correctly was dropped afterwards). `tests/test_v2.py` also holds 7 mutants, one per step: invisible strip, NFKC, case-insensitive scan, hex decode, URL decode, canonicalizing decoded strings, and the long-run fail-closed rule. Each turns the v2 table. All 184 existing tests pass unchanged (no existing test file is edited). `bash run.sh` printed 231 passed at v2.

Measured, with the numbers as printed:

| check | v1 | v2 |
|---|---|---|
| benign corpus over-block (benign.jsonl) | 4/47 | 4/47 (same four pinned rows; 0 rows from the long-run rule) |
| fuzz, new seed router-v2-check-20261004-s2, N=2000 attack | 1037/2000 = 0.518 [0.497, 0.540] | 642/2000 = 0.321 [0.301, 0.342] |
| fuzz false alarm, same seed, 1000 benign variants | 0/1000 [0.000, 0.004] | 0/1000 [0.000, 0.004] |
| fuzz solo bypass: hex_wrap | 1.000 | 0.337 |
| fuzz solo bypass: case_change | 0.714 | 0.262 |
| fuzz solo bypass: zero_width | 0.783 | 0.133 |
| blind eval, egress router rows only (46 attacks, 47 benign) | recall 0.39 [0.26, 0.54], 28 missed, precision 1.00 | recall 0.43 [0.30, 0.58], 26 missed, precision 1.00 |

The fuzz seed was written down before the run. It is an in-distribution check: the fuzz operators informed the fix, so the drop from 0.518 to 0.321 is not evidence about attacks nobody listed. The blind eval was not read or tuned against. Its two intervals overlap, so the gain from 28 to 26 missed is within noise. I did not run the old seed on v2.

## Hostile review 2026-10-04

An adversarial review of v2 (RED-RUN-REVIEW.txt, rows R1 to R18) found 18 defects. 18 of 18 fixed, each with a test in `tests/test_hostile.py` that failed first (20 failed, 1 passed before the fix) and passes now (260 passed in the full suite). Root cause of R1 to R9: a decoded view was dropped (a decode error or the 90% text gate) instead of scanned. Every decoded view is now scanned, with bad bytes replaced, and the gate is gone.

- R1, R2: one invalid UTF-8 byte no longer voids a base64 or hex view (decode with replace).
- R3: hex tries byte offsets 0 to 3, so a glued prefix cannot shift the key out of view.
- R4: base64 tries offsets 0 to 3, so a word glued to the front cannot shift the 4-character alignment.
- R5, R6: base64 and hex runs wrapped over lines are joined before decoding.
- R7, R8: base64 and hex bytes are also read as UTF-16 (both byte orders, both alignments).
- R9: control-byte padding no longer lowers a view under a text gate; there is no gate.
- R10, R11: variation selectors and U+034F are stripped in canonicalization.
- R12: control characters other than tab and newlines are stripped in canonicalization.
- R13: a JSON `\uXXXX` escape view is scanned.
- R14: a view of all JSON string values joined catches a key split over fields.
- R15, R16: PERSON matches Unicode letters (Zoe with a diaeresis, Jose, Rene, also percent-encoded).
- R17: PERSON allows apostrophes and hyphens inside a name (O'Brien).
- R18: the email pattern is bounded and runs only when the text holds an `@`; a 64k-character input takes under 1 second (test_R18_email_regex_bounded, was 3.3s at 16k and a hang at 160k).

Mutants: 6 new mutants in `tests/test_hostile.py` (json, base64, hex, utf-16 views, invisible strip, ASCII-only person) are each caught, 6 of 6. Measured: the evaluate.py table and the benign over-block are unchanged (45/45 sensitive local, 43/47 benign cloud, same four known rows). The repo has no fuzz or blind-eval script, so I did not re-measure the bypass rate; the 0.321 fuzz figure above is v2 before this review. A dense 64k input made only of long encoded runs takes about 2 seconds, because every run is decoded at four offsets and several encodings. Still not handled: everything in the v2 Limitations list.

## Honesty

This is a small deterministic router, not a product and not a data loss prevention system. The cases are synthetic and written for this repo. I did not test it against real traffic, real vendor APIs, a real local model or real people's data, and the benign corpus is small and written by the same author as the patterns. The destination names are labels and the costs are made-up numbers. The router decides where a prompt goes. It does not send the prompt, and it does not check that the destination keeps its side of the deal.

RED-RUN.txt is the first test run, made before router.py held any logic (a router that always picks cloud). It failed 74 of 179 tests for that reason. It was lightly edited after the run: the home path became `~`, and a private key header and a Slack token prefix were replaced with a redaction marker so the repo carries no secret-shaped text.

## Limitations

- A pattern scanner misses a paraphrase ("the code that starts with s k and then my cat's name"), a secret with no known prefix or shape, a name and a diagnosis that carry no person marker, and anything in an image or an attached file.
- Semantic attacks are out of scope. A prompt that asks the model to guess a secret, or that describes a patient without a name, a record number or a first-person phrase, routes cloud.
- Health detection needs a term plus a person marker (Patient, Mr, Mrs or Ms with a capitalized name, MRN, a first-person phrase, or a family member). Both halves are keyword lists and are short.
- Obfuscation handles spaces, dots and zero-width characters, and base64 and URL-safe base64. Hex, rot13, reversed text, homoglyphs and nested encodings are not handled. A private key header is matched as plain text and as base64 only.
- The classifier has no real timeout. The tests inject a timeout error to prove the fallback, and a real deployment needs a deadline around the call.
- The scan covers the messages passed in. If an application adds a system prompt, a file or a tool result after routing, those are not seen.
- It over-blocks. An email next to a phone number routes local, and so does a health term next to a capitalized word after Patient, Mr, Mrs or Ms.
- v2 still passes: homoglyphs (Cyrillic lookalikes are not folded to Latin; solo bypass 0.614 in the fuzz), punctuation and line breaks inside a key (only spaces, dots and format characters are skipped), nested encodings (base64 of hex: 15/15 bypass), hex with separators or 0x prefixes, rot13, reversed text, and binary or encrypted hex (it looks like a hash, so a hash-shaped run is routed cloud on purpose). Case-insensitive person markers also widen the health rule, so `patient` or `ms` followed by a word plus a health term routes local.
- Rule ids are a closed list. A class or rule added later needs a test and a mutant of its own.

## CI

The workflow in .github/workflows/ci.yml runs `python evaluate.py` and `python -m pytest -q` on push and pull request, with each action pinned to a commit.

## License

MIT, see LICENSE.
