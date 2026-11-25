"""Look-alike name detection against bundled lists of popular packages.

Lists: npm (npm-high-impact), PyPI (hugovk/top-pypi-packages), NuGet (search
API, by total downloads). Fully offline at check time.
"""
import functools
import re
from importlib import resources

# A name only counts as a typosquat suspect if it is ALSO not widely used.
# Popular-but-similar names (preact vs react) are filtered by this.
SUSPECT_MAX_DOWNLOADS = {"npm": 50_000, "pypi": 200_000, "nuget": 500_000}


@functools.lru_cache(maxsize=None)
def popular(eco):
    try:
        raw = resources.files("depbouncer.data").joinpath(f"popular-{eco}.txt").read_text(encoding="utf-8")
    except (FileNotFoundError, OSError):
        return frozenset()
    return frozenset(norm(eco, n) for n in raw.split() if n.strip())


def norm(eco, name):
    n = name.strip().lower()
    if eco == "pypi":
        n = re.sub(r"[-_.]+", "-", n)
    return n


def _squash(n):
    return re.sub(r"[-_.@/0-9]", "", n)


def _dl(a, b, limit):
    """Damerau-Levenshtein distance with early exit above `limit`."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2, prev = None, list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = a[i - 1] != b[j - 1]
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if prev2 is not None and i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > limit:
            return limit + 1
        prev2, prev = prev, cur
    return prev[-1]


def lookalike(eco, name):
    """Return the popular name this one imitates, or None."""
    pop = popular(eco)
    n = norm(eco, name)
    if not pop or n in pop:
        return None
    bare = n.split("/", 1)[1] if n.startswith("@") and "/" in n else n
    sq = _squash(bare)
    limit = 1 if len(bare) <= 7 else 2
    for p in pop:
        pb = p.split("/", 1)[1] if p.startswith("@") and "/" in p else p
        if len(pb) < 4:
            continue
        if bare == pb and n != p:          # @evil/lodash vs lodash
            return p
        if sq and sq == _squash(pb) and bare != pb:   # react_dom, reactdom2
            return p
        if _dl(bare, pb, limit) <= limit:
            return p
    return None
