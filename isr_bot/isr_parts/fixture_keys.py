# Part of isr.py: runs inside isr.py's namespace (loaded by _isr_part); not a module on its own.
# ---------------------------------------------------------------- 1.1.1: test fixture keys, recognized by construction
# Since Nov 5 a live audit graded F on a test's planted GitHub-shaped token echoed into a unittest log. A fixture is now made one
# way only, and recognized only when the whole value is exactly that construction:
#     <one of KEY_PREFIXES, longest match> + "ISRFIX" + <payload: version tag + seed characters> + <mac>
# <mac> is the start of sha256(FIX_SALT + prefix + payload), written in the alphabet that prefix allows. FIX_SALT is published:
# it is not a secret, it only proves the value was built here. No provider issues a token whose body starts with ISRFIX and ends
# in this MAC, so a real key (one with ISRFIX anywhere else, a wrong MAC, a short body, no prefix) is never a fixture and alerts
# as before. A key block (PEM) is never a fixture. Nothing here reads the path, the line or a word near the value.
FIX_SALT = "isr-bot-test-fixture-v1"
FIXTURE_MARK = "ISRFIX"
FIX_VERSION = "1"
FIX_ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
FIX_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
FIX_UPPER_PREFIXES = ("AKIA", "ASIA")   # their keys are upper case and digits only (ISR-T011, gitleaks' aws-access-token)
# prefixes whose key rule has a fixed body length (ISR-T011, SCRUB, gitleaks); any other takes the length it is given
FIX_FIXED = {"AKIA": 16, "ASIA": 16, "AIza": 35, "glpat-": 20, "ghp_": 36, "gho_": 36, "ghu_": 36, "ghs_": 36, "ghr_": 36}
FIX_MIN_REST = 8   # payload and MAC together after the marker, at least
FIX_MAC_MAX = 12
FIXTURE_PATHS = set()   # the files an audit found a fixture in this run (audit() clears it); paths only, never a value


def _fix_alphabet(prefix):
    return FIX_UPPER if prefix in FIX_UPPER_PREFIXES else FIX_ALNUM


def _fix_chars(material, alphabet, k):
    """k characters of `alphabet` from sha256 of `material` (and a counter, for more than one digest's worth)."""
    out, i = [], 0
    while len(out) < k:
        out += [alphabet[b % len(alphabet)] for b in hashlib.sha256(f"{material}|{i}".encode()).digest()]
        i += 1
    return "".join(out[:k])


def _fix_mac_len(rest):
    return min(FIX_MAC_MAX, rest // 2)


def _fix_mac(prefix, payload, k, alphabet):
    """The first k bytes of sha256(FIX_SALT + prefix + payload), each written as one character of `alphabet` (k <= 12)."""
    return "".join(alphabet[b % len(alphabet)] for b in hashlib.sha256((FIX_SALT + prefix + payload).encode()).digest()[:k])


def _fix_prefix_len(value):
    """The longest of KEY_PREFIXES at the start of value (0 when none is)."""
    return max((m.end() for m in (p.match(value) for p in KEY_PREFIXES) if m), default=0)


def fixture_body(prefix, n, seed=0):
    """The n characters make_isr_fixture puts after `prefix` (the marker, the payload, the MAC), for any n of 8 or more. Only the
    lengths make_isr_fixture accepts give a fixture; any other is a marked look-alike that is not one (tests use that)."""
    rest = n - len(FIXTURE_MARK)
    if rest < 2:
        raise ValueError("a fixture body needs at least 8 characters")
    alphabet, k = _fix_alphabet(prefix), _fix_mac_len(rest)
    payload = FIX_VERSION + _fix_chars(f"{FIX_SALT}|seed|{prefix}|{n}|{seed}", alphabet, rest - k - 1)
    return FIXTURE_MARK + payload + _fix_mac(prefix, payload, k, alphabet)


def make_isr_fixture(prefix, n, seed=0):
    """A key-shaped test value ISR Bot recognizes as its own fixture (is_isr_fixture): `prefix` (exactly one of KEY_PREFIXES) and
    a body of n characters. ValueError for a prefix or length that can't make one."""
    want = FIX_FIXED.get(prefix)
    if want is not None and n != want:
        raise ValueError(f"a {prefix} fixture's body is {want} characters")
    v = prefix + fixture_body(prefix, n, seed)
    if _fix_prefix_len(v) != len(prefix) or not is_isr_fixture(v):
        raise ValueError("not a key prefix ISR Bot can make a fixture for")
    return v


def is_isr_fixture(value):
    """True only when the whole of `value` is make_isr_fixture's construction: the longest of KEY_PREFIXES at its start, then
    FIXTURE_MARK right after it, a body of the prefix's fixed length (if it has one), the version tag, and the MAC. Linear in
    len(value); never a substring, a nearby word, the line or the path."""
    if not isinstance(value, str) or not value.isascii():
        return False
    k = _fix_prefix_len(value)
    if not k or not value.startswith(FIXTURE_MARK, k):
        return False
    prefix, body = value[:k], value[k:]
    want = FIX_FIXED.get(prefix)
    rest = len(body) - len(FIXTURE_MARK)
    if (want is not None and len(body) != want) or rest < FIX_MIN_REST:
        return False
    alphabet = _fix_alphabet(prefix)
    tail = body[len(FIXTURE_MARK):]
    allowed = frozenset(alphabet)
    if any(c not in allowed for c in tail):
        return False
    m = _fix_mac_len(rest)
    payload, mac = tail[:rest - m], tail[rest - m:]
    return payload.startswith(FIX_VERSION) and mac == _fix_mac(prefix, payload, m, alphabet)   # FIX_SALT is public: nothing to time


def keep_secret_hit(value, path=None):
    """The one test every secret hit goes through before a finding is made from it (ISR-S001, gitleaks' ISR-S002, ISR-T011 in
    scan_text): False only for an ISR Bot test fixture (is_isr_fixture). A value that couldn't be read back (None) is kept: fail
    closed. `path`: the file it is in, noted on FIXTURE_PATHS when it is a fixture, so the cleanup can still find it."""
    if isinstance(value, str) and is_isr_fixture(value):
        if path:
            FIXTURE_PATHS.add(os.path.abspath(path))
        return False
    return True
