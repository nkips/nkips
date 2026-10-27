#!/usr/bin/env python3
"""NKIP-0004 reference helpers: strict I-JSON parsing, the canonical form, the
kind 30078 event, BIP-340 Schnorr verification, verdicts and the revision gate.
Checks the vectors: python3 tools/nkip0004.py check nkips/nkip-0004/vectors/v1.json
Standard library only. Verification only; this file never signs."""
import hashlib, json, math, re, sys

KIND = 30078
MAX_SAFE = 2**53 - 1
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX128 = re.compile(r"^[0-9a-f]{128}$")

class Invalid(ValueError):
    pass

# ── strict I-JSON parsing (RFC 7493) ─────────────────────────────────────────
def _no_dupes(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)): raise Invalid("duplicate member")
    return dict(pairs)

def _int(s):
    i = int(s)
    if abs(i) > MAX_SAFE: raise Invalid("number out of range")
    return i

def _float(s):
    f = float(s)
    if not math.isfinite(f): raise Invalid("number out of range")
    return f

def _const(s):
    raise Invalid("number out of range")

def _check_strings(v):
    if isinstance(v, str):
        if any(0xD800 <= ord(ch) <= 0xDFFF for ch in v): raise Invalid("lone surrogate")
    elif isinstance(v, list):
        for x in v: _check_strings(x)
    elif isinstance(v, dict):
        for k, x in v.items(): _check_strings(k); _check_strings(x)

def parse(text):
    """JSON text -> value, or raises Invalid. Duplicates, unsafe integers, non-finite
    numbers and lone surrogates are refused (I-JSON)."""
    v = json.loads(text, object_pairs_hook=_no_dupes, parse_int=_int, parse_float=_float, parse_constant=_const)
    _check_strings(v)
    return v

# ── canonical form: RFC 8785 (JCS) ───────────────────────────────────────────
def es_number(x):
    """ECMAScript Number::toString, which RFC 8785 uses for numbers."""
    if isinstance(x, bool): raise TypeError
    if isinstance(x, int):
        if abs(x) > MAX_SAFE: raise Invalid("number out of range")
        x = float(x)
    if x == 0: return "0"
    if x < 0: return "-" + es_number(-x)
    r = repr(x)                                   # shortest round-trip digits
    mant, _, exp = r.partition("e")
    exp = int(exp) if exp else 0
    if "." in mant:
        ip, fp = mant.split(".")
    else:
        ip, fp = mant, ""
    digits = (ip + fp).lstrip("0")
    point = len(ip) + exp - (len(ip + fp) - len((ip + fp).lstrip("0")))
    digits = digits.rstrip("0")
    k, n = len(digits), point
    if k <= n <= 21: return digits + "0" * (n - k)
    if 0 < n <= 21: return digits[:n] + "." + digits[n:]
    if -6 < n <= 0: return "0." + "0" * (-n) + digits
    e = n - 1
    sign = "+" if e >= 0 else "-"
    m = digits[0] + ("." + digits[1:] if k > 1 else "")
    return f"{m}e{sign}{abs(e)}"

_ESC = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}

def es_string(s):
    """ECMAScript JSON.stringify string form (RFC 8785 §3.2.2.2)."""
    out = []
    for ch in s:
        if ch in _ESC: out.append(_ESC[ch])
        elif ord(ch) < 0x20: out.append("\\u%04x" % ord(ch))
        else: out.append(ch)
    return '"' + "".join(out) + '"'

def _utf16(k):
    return k.encode("utf-16-be")

def canonical(v):
    if v is None: return "null"
    if v is True: return "true"
    if v is False: return "false"
    if isinstance(v, (int, float)): return es_number(v)
    if isinstance(v, str): return es_string(v)
    if isinstance(v, list): return "[" + ",".join(canonical(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ",".join(es_string(k) + ":" + canonical(v[k]) for k in sorted(v, key=_utf16)) + "}"
    raise TypeError(type(v))

def has_member(v, name):
    if isinstance(v, dict): return name in v or any(has_member(x, name) for x in v.values())
    if isinstance(v, list): return any(has_member(x, name) for x in v)
    return False

# ── the Nostr event (NIP-01) ─────────────────────────────────────────────────
def event_id(pubkey, created_at, d, content):
    ser = "[0," + es_string(pubkey) + "," + str(created_at) + "," + str(KIND) + ',[["d",' + es_string(d) + "]]," + es_string(content) + "]"
    return hashlib.sha256(ser.encode()).hexdigest()

# ── BIP-340 Schnorr over secp256k1 ───────────────────────────────────────────
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

def _add(a, b):
    if a is None: return b
    if b is None: return a
    if a[0] == b[0] and (a[1] != b[1] or a[1] == 0): return None
    if a == b: lam = 3 * a[0] * a[0] * pow(2 * a[1], P - 2, P) % P
    else: lam = (b[1] - a[1]) * pow(b[0] - a[0], P - 2, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return (x, (lam * (a[0] - x) - a[1]) % P)

def _mul(pt, k):
    r = None
    while k:
        if k & 1: r = _add(r, pt)
        pt, k = _add(pt, pt), k >> 1
    return r

def _lift_x(x):
    if x >= P: return None
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if y * y % P != y2: return None
    return (x, y if y % 2 == 0 else P - y)

def _tagged(tag, data):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + data).digest()

def schnorr_verify(pubkey_hex, msg_hex, sig_hex):
    pk, m, sig = bytes.fromhex(pubkey_hex), bytes.fromhex(msg_hex), bytes.fromhex(sig_hex)
    pt = _lift_x(int.from_bytes(pk, "big"))
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if pt is None or r >= P or s >= N: return False
    e = int.from_bytes(_tagged("BIP0340/challenge", sig[:32] + pk + m), "big") % N
    R = _add(_mul(G, s), _mul(pt, N - e))
    return R is not None and R[1] % 2 == 0 and R[0] == r

# ── verdicts ─────────────────────────────────────────────────────────────────
def verdict(env, d, trusted):
    """-> (verdict, reason). `env` is a parsed envelope or a bare payload."""
    if not isinstance(env, dict): return "invalid", "not an object"
    if "manifest" not in env: return "unsigned", "bare payload"
    if set(env) - {"manifest", "signature"}: return "invalid", "unknown envelope member"
    payload, sig = env["manifest"], env.get("signature")
    if not isinstance(payload, dict): return "invalid", "payload is not an object"
    if "manifest" in payload: return "invalid", 'payload has a top-level member named "manifest"'
    if has_member(payload, "signature"): return "invalid", 'payload contains a member named "signature"'
    if sig is None: return "unsigned", "no signature"
    if not isinstance(sig, dict) or set(sig) != {"alg", "pubkey", "created_at", "sig"}: return "invalid", "malformed signature"
    if sig["alg"] != "nostr-schnorr": return "invalid", "unsupported alg"
    ca = sig["created_at"]
    if not (isinstance(sig["pubkey"], str) and HEX64.match(sig["pubkey"]) and isinstance(sig["sig"], str) and HEX128.match(sig["sig"])
            and isinstance(ca, int) and not isinstance(ca, bool) and 0 <= ca <= MAX_SAFE):
        return "invalid", "malformed signature"
    eid = event_id(sig["pubkey"], ca, d, canonical(payload))
    if not schnorr_verify(sig["pubkey"], eid, sig["sig"]): return "invalid", "signature does not verify"
    return ("verified" if sig["pubkey"] in trusted else "untrusted"), "ok"

def revision_gate(cached, revision, same_bytes):
    """-> (action, report): action 'apply' | 'keep' | 'refuse'. An equal revision never
    replaces the cached copy; report is True when its bytes differ (a publisher error
    the consumer MAY surface)."""
    if cached is None or revision > cached: return "apply", False
    if revision == cached: return "keep", not same_bytes
    return "refuse", False

def rotation(env, context, pinned):
    """-> (action, new_pin_or_reason): 'rotate' with the new key, or 'ignore' with why."""
    got, why = verdict(env, context + ":rotate", set(pinned))
    if got != "verified": return "ignore", "not signed by the pinned key" if got == "untrusted" else why
    p = env["manifest"]
    if p.get("id") != context + ":rotate": return "ignore", "id names another context"
    if not (isinstance(p.get("new_pubkey"), str) and HEX64.match(p["new_pubkey"])): return "ignore", "new_pubkey is not 64 lowercase hex"
    if not (isinstance(p.get("revision"), int) and not isinstance(p.get("revision"), bool)): return "ignore", "revision"
    return "rotate", p["new_pubkey"]

# ── vectors ──────────────────────────────────────────────────────────────────
def check(path):
    d = parse(open(path, encoding="utf-8").read())
    n = 0
    for v in d["valid"]:
        env = parse(json.dumps(v["envelope"], ensure_ascii=False))
        c = canonical(env["manifest"])
        assert c == v["canonical"], v["name"] + ": canonical bytes"
        assert hashlib.sha256(c.encode()).hexdigest() == v["canonical_sha256"], v["name"] + ": sha256"
        assert event_id(env["signature"]["pubkey"], env["signature"]["created_at"], v["d"], c) == v["event"]["id"], v["name"] + ": event id"
        assert v["event"]["tags"] == [["d", v["d"]]] and v["event"]["kind"] == KIND and v["event"]["content"] == c, v["name"] + ": event"
        got = verdict(env, v["d"], set(v["trusted_keys"]))[0]
        assert got == v["verdict"], f"{v['name']}: {got} != {v['verdict']}"
        n += 1
    for v in d["invalid"]:
        got, why = verdict(v["envelope"], v["d"], set())
        assert got == "invalid" and v["reason"] in why, f"{v['name']}: {got} ({why}), expected invalid ({v['reason']})"
        n += 1
    for v in d["text"]:
        try:
            got, why = verdict(parse(v["envelope_text"]), v["d"], set())
        except Invalid as e:
            got, why = "invalid", str(e)
        assert got == "invalid" and v["reason"] in why, f"{v['name']}: {got} ({why}), expected invalid ({v['reason']})"
        n += 1
    for v in d["unsigned"]:
        got = verdict(v["envelope"], v["d"], set())[0]
        assert got == "unsigned", f"{v['name']}: {got}"
        n += 1
    rp = d["replay"]
    for c in rp["cases"]:
        assert revision_gate(rp["cached"]["revision"], c["revision"], c["same_bytes"]) == (c["action"], c.get("report", False)), f"replay {c}"
        n += 1
    for v in d["rotations"]:
        act, out = rotation(v["envelope"], v["context"], v["pinned"])
        assert act == v["action"], f"{v['name']}: {act} ({out})"
        assert (out == v["new_pin"]) if act == "rotate" else (v["reason"] in out), f"{v['name']}: {out}"
        n += 1
    # es_number spot checks against ECMAScript (RFC 8785 Appendix B samples)
    for x, s in [(1e21, "1e+21"), (1e-7, "1e-7"), (0.1, "0.1"), (100.0, "100"), (5e-324, "5e-324"), (123456789012345.0, "123456789012345"),
                 (1.7976931348623157e308, "1.7976931348623157e+308"), (0.000001, "0.000001"), (-0.0, "0"), (333333333.3333333, "333333333.3333333")]:
        assert es_number(x) == s, f"es_number({x!r}) = {es_number(x)} != {s}"
    print(f"ok: {len(d['valid'])} valid, {len(d['invalid']) + len(d['text'])} invalid, {len(d['unsigned'])} unsigned, {len(rp['cases'])} replay cases, {len(d['rotations'])} rotation cases")

if __name__ == "__main__":
    if sys.argv[1:2] == ["check"]: check(sys.argv[2])
    else: print(__doc__)
