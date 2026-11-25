"""Small version-range resolvers. They return None when unsure, which the
caller turns into ASK (never a silent PASS)."""
import re

# ---------------------------------------------------------------- npm semver
_SEM = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")
_PART = re.compile(r"^v?(\d+|[xX*])(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?(?:-([0-9A-Za-z.-]+))?$")


def sem_parse(v):
    m = _SEM.match(v.strip())
    if not m:
        return None
    pre = tuple(int(p) if p.isdigit() else p for p in m.group(4).split(".")) if m.group(4) else None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), pre)


def _key(t):
    # pre-releases sort before the release
    pre = t[3]
    return (t[0], t[1], t[2], 0 if pre else 1,
            tuple((0, p) if isinstance(p, int) else (1, p) for p in (pre or ())))


def _cmp(a, b):
    ka, kb = _key(a), _key(b)
    return (ka > kb) - (ka < kb)


def _partial(tok):
    m = _PART.match(tok)
    if not m:
        return None
    nums = []
    for g in m.group(1, 2, 3):
        if g is None or g in "xX*":
            break
        nums.append(int(g))
    return nums, m.group(4)


def _comparators(tok):
    """Return list of (op, version tuple) for one token, or None."""
    op = ""
    for o in (">=", "<=", ">", "<", "=", "^", "~"):
        if tok.startswith(o):
            op, tok = o, tok[len(o):]
            break
    if op == "~" and tok.startswith(">"):
        tok = tok[1:]
    tok = tok.strip()
    if tok in ("", "*", "x", "X", "latest"):
        return [(">=", (0, 0, 0, None))]
    p = _partial(tok)
    if not p:
        return None
    nums, pre = p
    preT = tuple(int(x) if x.isdigit() else x for x in pre.split(".")) if pre else None
    full = nums + [0] * (3 - len(nums))
    lo = (full[0], full[1], full[2], preT if len(nums) == 3 else None)
    if len(nums) == 0:
        return [(">=", (0, 0, 0, None))]

    def bump(i):
        b = full[:]
        b[i] += 1
        for j in range(i + 1, 3):
            b[j] = 0
        return (b[0], b[1], b[2], (0,))  # (0,) = lowest pre-release of that version

    if op == "^":
        i = next((k for k, n in enumerate(full[: len(nums)]) if n != 0), len(nums) - 1)
        if len(nums) < 3 and all(n == 0 for n in nums):
            i = len(nums) - 1
        return [(">=", lo), ("<", bump(i))]
    if op == "~":
        i = 1 if len(nums) >= 2 else 0
        return [(">=", lo), ("<", bump(i))]
    if op in ("", "="):
        if len(nums) == 3:
            return [("=", lo)]
        return [(">=", lo), ("<", bump(len(nums) - 1))]
    if op == ">" and len(nums) < 3:
        return [(">=", bump(len(nums) - 1))]
    if op == "<=" and len(nums) < 3:
        return [("<", bump(len(nums) - 1))]
    return [(op, lo)]


def _sat(v, comps):
    for op, c in comps:
        r = _cmp(v, c)
        ok = {"=": r == 0, ">=": r >= 0, "<=": r <= 0, ">": r > 0, "<": r < 0}[op]
        if not ok:
            return False
    return True


def npm_resolve(spec, versions):
    """Highest version satisfying an npm range; None if unsure."""
    spec = spec.strip()
    sets = []
    for alt in spec.split("||"):
        alt = alt.strip()
        hy = re.match(r"^(\S+)\s+-\s+(\S+)$", alt)
        if hy:
            a, b = _comparators(">=" + hy.group(1)), _comparators("<=" + hy.group(2))
            if a is None or b is None:
                return None
            sets.append(a + b)
            continue
        alt = re.sub(r"(>=|<=|>|<|=|\^|~)\s+", r"\1", alt)
        comps = []
        for tok in alt.split():
            c = _comparators(tok)
            if c is None:
                return None
            comps += c
        sets.append(comps or [(">=", (0, 0, 0, None))])
    allow_pre = "-" in spec
    best = None
    for v in versions:
        t = sem_parse(v)
        if not t or (t[3] and not allow_pre):
            continue
        if any(_sat(t, s) for s in sets) and (best is None or _cmp(t, best[0]) > 0):
            best = (t, v)
    return best[1] if best else None


# ------------------------------------------------------------- PEP 440 (pip)
_PEP = re.compile(r"^v?(\d+(?:\.\d+)*)((?:a|b|rc|alpha|beta|c|pre|preview|dev)[.-]?\d*|\.dev\d*)?(\.post\d+)?(\+.*)?$", re.I)


def pep_parse(v):
    m = _PEP.match(v.strip())
    if not m:
        return None
    rel = tuple(int(x) for x in m.group(1).split("."))
    return rel, bool(m.group(2))


def _norm(rel, n):
    return rel + (0,) * (n - len(rel))


def _pep_cmp(a, b):
    n = max(len(a), len(b))
    a, b = _norm(a, n), _norm(b, n)
    return (a > b) - (a < b)


def pep_satisfies(v, spec):
    p = pep_parse(v)
    if not p:
        return None
    rel = p[0]
    for part in [s.strip() for s in spec.split(",") if s.strip()]:
        m = re.match(r"^(===|==|!=|~=|>=|<=|>|<)\s*(.+)$", part)
        if not m:
            return None
        op, target = m.groups()
        if op == "===":
            if v != target:
                return False
            continue
        if target.endswith(".*") and op in ("==", "!="):
            pre = tuple(int(x) for x in target[:-2].split(".") if x.isdigit())
            match = rel[: len(pre)] == pre
            if (op == "==") != match:
                return False
            continue
        t = pep_parse(target)
        if not t:
            return None
        r = _pep_cmp(rel, t[0])
        if op == "~=":
            if len(t[0]) < 2 or r < 0 or rel[: len(t[0]) - 1] != t[0][:-1]:
                return False
            continue
        ok = {"==": r == 0, "!=": r != 0, ">=": r >= 0, "<=": r <= 0, ">": r > 0, "<": r < 0}[op]
        if not ok:
            return False
    return True


def pypi_resolve(spec, versions):
    best = None
    for v in versions:
        p = pep_parse(v)
        if not p or p[1]:
            continue
        s = pep_satisfies(v, spec)
        if s is None:
            return None
        if s and (best is None or _pep_cmp(p[0], best[0]) > 0):
            best = (p[0], v)
    return best[1] if best else None


# --------------------------------------------------------------------- NuGet
def nuget_resolve(spec, versions):
    """NuGet picks the LOWEST version that satisfies. Plain '1.2.3' means >= 1.2.3."""
    spec = spec.strip()
    if not spec:
        return None
    m = re.match(r"^([\[(])\s*([^,\])]*)\s*(?:,\s*([^\])]*))?\s*([\])])$", spec)
    if m:
        lo_inc, lo, hi, hi_inc = m.group(1) == "[", m.group(2), m.group(3), m.group(4) == "]"
        if m.group(3) is None:  # [1.0] exact
            return lo.lower() if lo.lower() in versions else None
    else:
        lo, hi, lo_inc, hi_inc = spec, None, True, False
    lo_t = pep_parse(lo) if lo else None
    hi_t = pep_parse(hi) if hi else None
    if (lo and not lo_t) or (hi and not hi_t):
        return None
    cands = []
    for v in versions:
        p = pep_parse(v)
        if not p or ("-" in v and "-" not in spec):
            continue
        if lo_t:
            r = _pep_cmp(p[0], lo_t[0])
            if r < 0 or (r == 0 and not lo_inc):
                continue
        if hi_t:
            r = _pep_cmp(p[0], hi_t[0])
            if r > 0 or (r == 0 and not hi_inc):
                continue
        cands.append((p[0], v))
    if not cands:
        return None
    cands.sort(key=lambda c: _norm(c[0], 6))
    return cands[0][1]


EXACT = re.compile(r"^[A-Za-z0-9.+!_-]+$")
