import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))
import router


def test_no_key_shaped_literal_in_any_tracked_file():
    files = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.split("\n")
    files = [f for f in files if f]
    assert files, "git ls-files returned nothing"
    shapes = [rx for _, rx in router.SECRET_PLAIN + router.SECRET_SPACED] + [router.PRIVATE_KEY]
    hits = []
    for f in files:
        text = (ROOT / f).read_text(errors="ignore")
        hits += [(f, rx.pattern[:30]) for rx in shapes if rx.search(text)]
    assert not hits, f"key-shaped literals tracked: {len(hits)} {hits[:5]}"
