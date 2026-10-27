#!/usr/bin/env python3
"""NKIP-0001 reference helpers: JCS (subset), sign/verify, commitment.
Generates test vectors: python3 tools/nkip0001.py gen > nkips/nkip-0001/vectors/v1.json
Checks them:           python3 tools/nkip0001.py check nkips/nkip-0001/vectors/v1.json
JCS subset: receipts contain only strings and integers with ASCII keys, for which
RFC 8785 equals sorted keys + no whitespace + UTF-8. Floats are rejected."""
import base64, hashlib, json, sys
from nacl.signing import SigningKey, VerifyKey

def jcs(obj):
    def chk(o):
        if isinstance(o, float): raise ValueError("floats not allowed")
        if isinstance(o, dict): [chk(v) for v in o.values()]
    chk(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
unb64u = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
key_id = lambda pk: hashlib.sha256(pk).hexdigest()[:16]

def sign(receipt, sk):
    r = {k: v for k, v in receipt.items() if k != "sig"}
    r["key_id"] = key_id(bytes(sk.verify_key))
    r["sig"] = b64u(sk.sign(jcs(r)).signature)
    return r

def verify(receipt, pk):
    r = {k: v for k, v in receipt.items() if k != "sig"}
    if r.get("key_id") != key_id(pk): return False
    try: VerifyKey(pk).verify(jcs(r), unb64u(receipt["sig"])); return True
    except Exception: return False

def commitment(issuer, deposit, payout):
    return hashlib.sha256(b"\x00".join([b"nkip01/1", issuer.encode(), deposit.encode(), payout.encode()])).hexdigest()

def attestation(receipt, sk):
    a = {"v": receipt["v"], "issuer": receipt["issuer"],
         "commitment": commitment(receipt["issuer"], receipt["deposit_address"], receipt["payout_address"]),
         "created_at": receipt["created_at"], "key_id": key_id(bytes(sk.verify_key))}
    a["sig"] = b64u(sk.sign(jcs(a)).signature)
    return a

def merkle_root(commitments):
    """RFC 6962 tree over sorted commitments (hex)."""
    nodes = [hashlib.sha256(b"\x00" + bytes.fromhex(c)).digest() for c in sorted(commitments)]
    if not nodes: return hashlib.sha256(b"").hexdigest()
    def mth(n):
        if len(n) == 1: return n[0]
        k = 1
        while k * 2 < len(n): k *= 2
        return hashlib.sha256(b"\x01" + mth(n[:k]) + mth(n[k:])).digest()
    return mth(nodes).hex()

def gen():
    sk = SigningKey(hashlib.sha256(b"nkip-0001 test key - DO NOT USE").digest())
    pk = bytes(sk.verify_key)
    policy = b"Example refund policy v1: deposits within 1% of deposit_amount are honoured.\n"
    base = {"v": "nkip01/1", "issuer": "example.swap", "order_id": "EX-0001",
            "deposit_asset": "XMR", "deposit_address": "84ExampleXmrDepositAddress0001",
            "deposit_amount": "1500000000000", "payout_asset": "BTC",
            "payout_address": "bc1qexamplepayoutaddress0001", "payout_amount": "820000",
            "rate_type": "fixed", "created_at": 1793000000, "expires_at": 1793001800,
            "policy_hash": hashlib.sha256(policy).hexdigest()}
    good = sign(base, sk)
    tampered = dict(good, payout_address="bc1qattackeraddress")
    att = attestation(good, sk)
    leaves = [commitment("example.swap", f"84ExampleXmrDepositAddress{i:04d}", "bc1qexamplepayoutaddress0001") for i in range(1, 6)]
    manifest = {"v": "nkip01/1", "issuer": "example.swap", "adopted_at": 1793000000,
                "keys": [{"key_id": key_id(pk), "alg": "ed25519", "public_key": b64u(pk), "not_before": 1793000000,
                          "revoked_at": None, "rotated_from": None, "rotation_sig": None}],
                "nostr_pubkey": "0" * 64, "relays": ["wss://relay.example.org", "wss://relay.example.net", "wss://relay.example.com"],
                "policies": [{"policy_hash": hashlib.sha256(policy).hexdigest(), "url": "https://example.swap/policy/v1.txt"}],
                "disputes": {"email": "disputes@example.swap"}}
    return {"public_key_b64u": b64u(pk), "key_id": key_id(pk), "policy_text": policy.decode(), "manifest": manifest,
            "attestation": att, "merkle": {"leaves": sorted(leaves), "root": merkle_root(leaves)},
            
            "vectors": [
              {"name": "valid", "receipt": good, "jcs_without_sig": jcs({k: v for k, v in good.items() if k != "sig"}).decode(),
               "valid": True, "commitment": commitment(good["issuer"], good["deposit_address"], good["payout_address"])},
              {"name": "tampered-payout", "receipt": tampered, "valid": False}]}

def check(path):
    d = json.load(open(path)); pk = unb64u(d["public_key_b64u"]); ok = True
    for v in d["vectors"]:
        r = verify(v["receipt"], pk)
        if r != v["valid"]: ok = False; print("FAIL sig", v["name"])
        if "commitment" in v and commitment(v["receipt"]["issuer"], v["receipt"]["deposit_address"], v["receipt"]["payout_address"]) != v["commitment"]:
            ok = False; print("FAIL commitment", v["name"])
    a = dict(d["attestation"]); sig = a.pop("sig")
    try: VerifyKey(pk).verify(jcs(a), unb64u(sig))
    except Exception: ok = False; print("FAIL attestation sig")
    if a["commitment"] != d["vectors"][0]["commitment"]: ok = False; print("FAIL attestation commitment")
    if merkle_root(d["merkle"]["leaves"]) != d["merkle"]["root"]: ok = False; print("FAIL merkle")
    print("OK" if ok else "FAILED"); sys.exit(0 if ok else 1)

# ── v2 (nkip01/2): salted commitment + salt box for XMR payouts ──────────────
# Needs pycryptodome (via tools/nkip0003.py, which holds the ed25519 + Monero
# address code). Run: python3 tools/nkip0001.py gen2 | check2 <file>
import os

def commitment_v2(issuer, deposit, payout, salt_hex):
    salt = bytes.fromhex(salt_hex)
    assert len(salt) == 32
    return hashlib.sha256(b"\x00".join([b"nkip01/2", issuer.encode(), deposit.encode(), payout.encode()]) + b"\x00" + salt).hexdigest()

def _n3():
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import nkip0003
    return nkip0003

def _box_key(derivation_bytes):
    return hashlib.sha256(b"nkip01/2 salt\x00" + derivation_bytes).digest()

def salt_box(payout_address, salt_hex, r=None):
    """Encrypt the salt to a Monero payout address. Primary address: R = r*G;
    subaddress: R = r*S (its spend key). In both cases the derivation is 8*r*V,
    which the wallet recomputes as 8*v*R with its private view key."""
    n3 = _n3()
    prefix = n3.b58decode(payout_address)[0]
    if prefix not in (18, 42): raise ValueError("salt box needs a standard address or subaddress")
    spend, view = n3.address_keys(payout_address)
    while r is None or r % n3.L == 0:
        r = int.from_bytes(os.urandom(64), "little") % n3.L
    base = n3.G if prefix == 18 else n3._dec(spend)
    R = n3._mul(base, r)
    der = n3._mul(n3._mul(n3._dec(view), r), 8)
    k = _box_key(n3._enc(der))
    ct = bytes(a ^ b for a, b in zip(bytes.fromhex(salt_hex), k))
    return {"r": n3._enc(R).hex(), "ct": ct.hex()}

def open_salt_box(box, private_view_key_hex):
    n3 = _n3()
    v = int.from_bytes(bytes.fromhex(private_view_key_hex), "little")
    der = n3._mul(n3._mul(n3._dec(bytes.fromhex(box["r"])), v), 8)
    k = _box_key(n3._enc(der))
    return bytes(a ^ b for a, b in zip(bytes.fromhex(box["ct"]), k)).hex()

def gen2():
    n3 = _n3()
    w = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "nkips", "nkip-0003", "vectors", "v1.json")))["test_wallet"]
    sk = SigningKey(hashlib.sha256(b"sip-0001 test key - DO NOT USE").digest())
    pk = bytes(sk.verify_key)
    policy_hash = hashlib.sha256(b"Example refund policy v1: deposits within 1% of deposit_amount are honoured.\n").hexdigest()
    cases = []
    for name, payout, r in [("BTC to XMR, primary address", w["primary_address"], 7), ("BTC to XMR, subaddress", w["subaddress_0_1"], 11)]:
        salt = hashlib.sha256(("nkip01/2 test salt " + name).encode()).hexdigest()
        rec = {"v": "nkip01/2", "issuer": "example.swap", "order_id": "EX-V2-" + str(r), "deposit_asset": "BTC",
               "deposit_address": "bc1qexampledepositv2" + str(r), "deposit_amount": "820000", "payout_asset": "XMR",
               "payout_address": payout, "payout_amount": "1500000000000", "rate_type": "fixed",
               "created_at": 1793000000, "expires_at": 1793003660, "policy_hash": policy_hash, "salt": salt}
        rec = sign(rec, sk)
        c = commitment_v2(rec["issuer"], rec["deposit_address"], rec["payout_address"], salt)
        box = salt_box(payout, salt, r)
        att = {"v": "nkip01/2", "issuer": rec["issuer"], "commitment": c, "created_at": rec["created_at"], "key_id": key_id(pk), "salt_box": box}
        att["sig"] = b64u(sk.sign(jcs(att)).signature)
        cases.append({"name": name, "receipt": rec, "commitment": c, "attestation": att})
    xmr_in = {"v": "nkip01/2", "issuer": "example.swap", "order_id": "EX-V2-XMRIN", "deposit_asset": "XMR",
              "deposit_address": w["subaddress_0_1"], "deposit_amount": "1500000000000", "payout_asset": "BTC",
              "payout_address": "bc1qexamplepayoutv2", "payout_amount": "820000", "rate_type": "fixed",
              "created_at": 1793000000, "expires_at": 1793003660, "policy_hash": policy_hash, "salt": "00" * 32}
    xmr_in = sign(xmr_in, sk)
    cases.append({"name": "XMR to BTC, zero salt (Monero deposit address is not observable)", "receipt": xmr_in,
                  "commitment": commitment_v2(xmr_in["issuer"], xmr_in["deposit_address"], xmr_in["payout_address"], "00" * 32)})
    return {"public_key_b64u": b64u(pk), "test_wallet_private_view_key": w["private_view_key"], "cases": cases,
            "note": "Test keys only; the wallet is the throwaway NKIP-0003 test wallet. Never send funds."}

def check2(path):
    d = json.load(open(path)); pk = unb64u(d["public_key_b64u"]); ok = True
    for c in d["cases"]:
        rec = c["receipt"]
        if not verify(rec, pk): ok = False; print("FAIL receipt sig", c["name"])
        if commitment_v2(rec["issuer"], rec["deposit_address"], rec["payout_address"], rec["salt"]) != c["commitment"]:
            ok = False; print("FAIL commitment", c["name"])
        if "attestation" in c:
            a = dict(c["attestation"]); sig = a.pop("sig")
            try: VerifyKey(pk).verify(jcs(a), unb64u(sig))
            except Exception: ok = False; print("FAIL attestation sig", c["name"])
            if a["commitment"] != c["commitment"]: ok = False; print("FAIL attestation commitment", c["name"])
            if open_salt_box(a["salt_box"], d["test_wallet_private_view_key"]) != rec["salt"]:
                ok = False; print("FAIL salt box", c["name"])
            wrong = hashlib.sha256(b"not the view key").hexdigest()
            if open_salt_box(a["salt_box"], wrong) == rec["salt"]: ok = False; print("FAIL salt box opens with a wrong key", c["name"])
    print("OK v2" if ok else "FAILED"); sys.exit(0 if ok else 1)

if __name__ == "__main__":
    if sys.argv[1:2] == ["gen"]: print(json.dumps(gen(), indent=2))
    elif sys.argv[1:2] == ["check"]: check(sys.argv[2])
    elif sys.argv[1:2] == ["gen2"]: print(json.dumps(gen2(), indent=2))
    elif sys.argv[1:2] == ["check2"]: check2(sys.argv[2])
    else: print(__doc__)
