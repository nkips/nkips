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

if __name__ == "__main__":
    if sys.argv[1:2] == ["gen"]: print(json.dumps(gen(), indent=2))
    elif sys.argv[1:2] == ["check"]: check(sys.argv[2])
    else: print(__doc__)
