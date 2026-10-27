#!/usr/bin/env python3
"""NKIP-0003 reference helpers: challenge parsing, the canonical message, and Monero
message-signature verification (SigV1 and SigV2, spend or view mode).
Checks the vectors: python3 tools/nkip0003.py check nkips/nkip-0003/vectors/v1.json
Needs pycryptodome (Keccak-256, the pre-SHA-3 padding Monero uses).
Verification only; this file never signs. The vector signatures were made by
monero-wallet-rpc v0.18.4.5 `sign` (SigV2) and checked with its `verify`."""
import hashlib, json, re, sys
from datetime import datetime
from urllib.parse import parse_qsl, urlsplit
from Crypto.Hash import keccak

# ── challenge + message ──────────────────────────────────────────────────────
REQUIRED = ["address", "nonce", "session", "origin", "handle", "dk", "issued_at", "expires_at", "return_url"]
CTRL = re.compile(r"[\x00-\x1f\x7f]")
ORIGIN = re.compile(r"^[a-z0-9.-]+(:\d+)?$", re.I)
DK = re.compile(r"^[0-9a-f]{16}$")
ADDRESS = re.compile(r"^[48][1-9A-HJ-NP-Za-km-z]{94}$")

class Refused(ValueError):
    pass

def iso(s):
    if not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,3})?Z", s): raise Refused("time not ISO 8601 UTC")
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()

def parse_challenge(uri):
    """Challenge URI -> dict, or raises Refused(reason). Mirrors the Wallet rules."""
    if not uri.startswith("monero-signin:"): raise Refused("not a monero-signin URI")
    query = uri.split("?", 1)[1] if "?" in uri else ""
    pairs = parse_qsl(query, keep_blank_values=True)
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)): raise Refused("duplicate parameter")
    p = dict(pairs)
    if p.get("v") != "1": raise Refused("unsupported version")
    p.setdefault("purpose", "login")
    for k in REQUIRED + ["purpose"]:
        if not p.get(k): raise Refused(f"missing {k}")
        if CTRL.search(p[k]): raise Refused(f"control character in {k}")
    if not ORIGIN.match(p["origin"]): raise Refused("origin is not a bare host")
    if not DK.match(p["dk"]): raise Refused("dk is not 16 lowercase hex")
    if not ADDRESS.match(p["address"]): raise Refused("address is not a 95-character standard address or subaddress")
    if len(p["nonce"]) < 16: raise Refused("nonce shorter than 16 characters")
    u = urlsplit(p["return_url"])
    if u.username is not None or u.password is not None or "#" in p["return_url"]:
        raise Refused("return_url must not carry credentials or a fragment")
    if not (u.scheme == "https" or (u.scheme == "http" and u.hostname in {"localhost", "127.0.0.1", "::1"})) or not u.netloc:
        raise Refused("return_url must be https (http only to loopback)")
    iat, exp = iso(p["issued_at"]), iso(p["expires_at"])
    if not (iat < exp <= iat + 15 * 60): raise Refused("time window must be > 0 and <= 15 minutes")
    return p

def message(c):
    return "\n".join([
        f"{c['origin']} wants you to sign in with your Monero address:", c["address"], "",
        f"Sign in to {c['origin']} as @{c['handle']}. This proves you control this address. No funds move.", "",
        f"Purpose: {c['purpose']}", f"Handle: {c['handle']}", f"Nonce: {c['nonce']}", f"Device-Key: {c['dk']}",
        f"Issued-At: {c['issued_at']}", f"Expiration-Time: {c['expires_at']}", "Version: 1",
    ])

def same_site(c):
    host = (urlsplit(c["return_url"]).hostname or "").lower()
    o = re.sub(r":\d+$", "", c["origin"].lower())
    return host == o or host.endswith("." + o)

# ── ed25519 group (Monero's curve) ───────────────────────────────────────────
Q = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, Q - 2, Q) % Q
SQRTM1 = pow(2, (Q - 1) // 4, Q)

def _add(P, R):
    (x1, y1), (x2, y2) = P, R
    t = D * x1 * x2 * y1 * y2
    return ((x1 * y2 + x2 * y1) * pow(1 + t, Q - 2, Q) % Q, (y1 * y2 + x1 * x2) * pow(1 - t, Q - 2, Q) % Q)

def _mul(P, e):
    R = (0, 1)
    while e:
        if e & 1: R = _add(R, P)
        P, e = _add(P, P), e >> 1
    return R

def _dec(b):
    y = int.from_bytes(b, "little") & ((1 << 255) - 1)
    if y >= Q: raise ValueError("bad point")
    xx = (y * y - 1) * pow(D * y * y + 1, Q - 2, Q) % Q
    x = pow(xx, (Q + 3) // 8, Q)
    if (x * x - xx) % Q: x = x * SQRTM1 % Q
    if (x * x - xx) % Q: raise ValueError("bad point")
    if x == 0 and b[31] >> 7: raise ValueError("bad point")
    if (x & 1) != b[31] >> 7: x = Q - x
    return (x, y)

def _enc(P):
    x, y = P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")

G = (_dec(_enc((15112221349535400772501151409588531511454012693041857206046113283949847762202,
                46316835694926478169428394003475163141307993866256225615783033603165251855960))))

def keccak256(b):
    h = keccak.new(digest_bits=256); h.update(b); return h.digest()

def hash_to_scalar(b):
    return int.from_bytes(keccak256(b), "little") % L

# ── Monero base58 + addresses ────────────────────────────────────────────────
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
ENC_SIZES = [0, 2, 3, 5, 6, 7, 9, 10, 11]

def b58decode(s):
    out = b""
    for i in range(0, len(s), 11):
        blk = s[i:i + 11]
        n = 0
        for ch in blk: n = n * 58 + ALPHABET.index(ch)
        size = ENC_SIZES.index(len(blk))
        out += n.to_bytes(size, "big")
    return out

def address_keys(addr):
    """Mainnet standard address (prefix 18) or subaddress (42) -> (spend_pub, view_pub)."""
    raw = b58decode(addr)
    if len(raw) != 69 or raw[0] not in (18, 42): raise ValueError("not a mainnet standard address or subaddress")
    if keccak256(raw[:65])[:4] != raw[65:]: raise ValueError("bad address checksum")
    return raw[1:33], raw[33:65]

def _varint(n):
    out = b""
    while True:
        b = n & 0x7F; n >>= 7
        out += bytes([b | 0x80]) if n else bytes([b])
        if not n: return out

def verify_signature(data, address, sig):
    """-> 'spend' | 'view' | None, as monero-wallet-rpc `verify` decides."""
    spend, view = address_keys(address)
    if sig.startswith("SigV1"):
        hashes = {"spend": (keccak256(data.encode()), spend)}
    elif sig.startswith("SigV2"):
        def h(mode):
            return keccak256(b"MoneroMessageSignature\x00" + spend + view + bytes([mode]) + _varint(len(data.encode())) + data.encode())
        hashes = {"spend": (h(0), spend), "view": (h(1), view)}
    else:
        return None
    raw = b58decode(sig[5:])
    if len(raw) != 64: return None
    c, r = int.from_bytes(raw[:32], "little"), int.from_bytes(raw[32:], "little")
    if c >= L or r >= L: return None
    for mode, (H, pub) in hashes.items():
        P = _dec(pub)
        comm = _add(_mul(G, r), _mul(P, c))
        if hash_to_scalar(H + pub + _enc(comm)) == c: return mode
    return None

# ── vectors ──────────────────────────────────────────────────────────────────
def check(path):
    d = json.load(open(path))
    for v in d["valid"]:
        c = parse_challenge(v["uri"])
        m = message(c)
        assert m == v["message"], v["name"] + ": message bytes"
        assert hashlib.sha256(m.encode()).hexdigest() == v["message_sha256"], v["name"] + ": sha256"
        assert hashlib.sha256(v["device_pubkey"].encode()).hexdigest()[:16] == c["dk"], v["name"] + ": dk"
        assert same_site(c) == v["callback_same_site"], v["name"] + ": same-site flag"
        for s in v["signatures"]:
            assert verify_signature(m, c["address"], s) == "spend", v["name"] + ": signature " + s[:5]
            assert verify_signature(m + "\n", c["address"], s) is None, v["name"] + ": trailing newline must fail"
            other = message(dict(c, origin="example.com"))
            assert verify_signature(other, c["address"], s) is None, v["name"] + ": other origin must fail"
    for v in d["invalid"]:
        try:
            parse_challenge(v["uri"])
        except Refused as e:
            assert v["reason"] in str(e), f"{v['name']}: refused for '{e}', expected '{v['reason']}'"
            continue
        raise AssertionError(v["name"] + ": accepted, expected refusal")
    for v in d.get("bad_signatures", []):
        assert verify_signature(v["message"], v["address"], v["signature"]) != "spend", v["name"]
    print(f"ok: {len(d['valid'])} valid, {len(d['invalid'])} invalid, {len(d.get('bad_signatures', []))} bad signatures")

if __name__ == "__main__":
    if sys.argv[1:2] == ["check"]: check(sys.argv[2])
    else: print(__doc__)
