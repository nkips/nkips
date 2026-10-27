#!/usr/bin/env python3
"""NKIP-0006 reference helpers (stdlib only): OpenPGP armor + packet headers, v4
fingerprints, the recipient key id a message names, v2 channel tags, and the event,
invite and receive rules. No PGP decryption or signature checks: the v2 example in the
vectors carries the test private keys so implementations can do those themselves.
Checks the vectors: python3 tools/nkip0006.py check nkips/nkip-0006/vectors/v1.json"""
import base64, hashlib, hmac, json, re, sys

# ── OpenPGP armor and packets ────────────────────────────────────────────────
def crc24(data):
    crc = 0xB704CE
    for b in data:
        crc ^= b << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000: crc ^= 0x1864CFB
    return crc & 0xFFFFFF

def dearmor(text, kind):
    """-> (headers, body bytes). Raises ValueError on a bad block or CRC."""
    begin, end = f"-----BEGIN PGP {kind}-----", f"-----END PGP {kind}-----"
    i, j = text.find(begin), text.find(end)
    if i < 0 or j < 0: raise ValueError(f"no PGP {kind} block")
    lines = text[i + len(begin):j].strip("\r\n").splitlines()
    headers = []
    while lines and lines[0].strip():
        if ":" not in lines[0]: break
        headers.append(lines.pop(0))
    if lines and not lines[0].strip(): lines.pop(0)
    crc = None
    if lines and lines[-1].startswith("="):
        crc = int.from_bytes(base64.b64decode(lines.pop()[1:]), "big")
    body = base64.b64decode("".join(l.strip() for l in lines))
    if crc is not None and crc != crc24(body): raise ValueError("armor CRC mismatch")
    return headers, body

def packets(data):
    """Yield (tag, body) for each packet (new and old formats; partial lengths joined)."""
    p = 0
    while p < len(data):
        h = data[p]; p += 1
        if not h & 0x80: raise ValueError("bad packet header")
        if h & 0x40:
            tag, body = h & 0x3F, b""
            while True:
                o = data[p]
                if o < 192: n, p = o, p + 1; body += data[p:p + n]; p += n; break
                if o < 224: n, p = ((o - 192) << 8) + data[p + 1] + 192, p + 2; body += data[p:p + n]; p += n; break
                if o == 255: n, p = int.from_bytes(data[p + 1:p + 5], "big"), p + 5; body += data[p:p + n]; p += n; break
                n, p = 1 << (o & 0x1F), p + 1; body += data[p:p + n]; p += n   # partial body length
        else:
            tag, lt = (h >> 2) & 0x0F, h & 3
            if lt == 3: n = len(data) - p
            else:
                w = [1, 2, 4][lt]; n = int.from_bytes(data[p:p + w], "big"); p += w
            body = data[p:p + n]; p += n
        yield tag, body

def v4_fingerprint(key_body):
    if key_body[0] != 4: raise ValueError("only v4 keys are fingerprinted here")
    return hashlib.sha1(b"\x99" + len(key_body).to_bytes(2, "big") + key_body).hexdigest().upper()

def key_info(armored):
    """Public key -> {fingerprint, subkey_ids} (v4)."""
    _, body = dearmor(armored, "PUBLIC KEY BLOCK")
    fp, subs = None, []
    for tag, b in packets(body):
        if tag == 6 and fp is None: fp = v4_fingerprint(b)
        elif tag == 14: subs.append(v4_fingerprint(b)[-16:])
    if not fp: raise ValueError("no primary key packet")
    return {"fingerprint": fp, "subkey_ids": subs}

WILDCARD = "*"

def message_recipients(armored):
    """Encrypted message -> armor headers + the recipient each PKESK packet names:
    v3 (RFC 4880/9580) a key id, v6 (RFC 9580) a fingerprint; WILDCARD when hidden
    (v3 key id of all zeros, or v6 with an empty key-version+fingerprint field)."""
    headers, body = dearmor(armored, "MESSAGE")
    ids = []
    for tag, b in packets(body):
        if tag != 1: continue
        if b[0] == 3:
            kid = b[1:9].hex().upper()
            ids.append(WILDCARD if kid == "0" * 16 else kid)
        elif b[0] == 6:
            n = b[1]
            ids.append(WILDCARD if n == 0 else b[3:2 + n].hex().upper())
        else:
            raise ValueError(f"PKESK version {b[0]} not handled")
    return headers, ids

# ── v1 (deployed, deprecated): what an observer reads without any key ───────
def v1_observe(event):
    topic = next((t[1] for t in event["tags"] if t[0] == "t"), "")
    m_topic = re.fullmatch(r"ghost-([0-9A-F]{8})", topic)
    m_head = re.match(r"^\[[^\]:]+: ([0-9A-F]{8})\]\n", event["content"])
    _, ids = message_recipients(event["content"])
    return {"topic_fp8": m_topic and m_topic.group(1), "header_fp8": m_head and m_head.group(1), "recipient_key_ids": ids}

# ── v2 ───────────────────────────────────────────────────────────────────────
KIND = 9061
HEX32 = re.compile(r"^[0-9a-f]{32}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
FPR = re.compile(r"^([0-9A-F]{40}|[0-9A-F]{64})$")

def epoch(created_at):
    return created_at // 86400

def channel_tag(chan_hex, created_at):
    msg = b"nkip06/2 tag" + epoch(created_at).to_bytes(8, "big")
    return hmac.new(bytes.fromhex(chan_hex), msg, hashlib.sha256).hexdigest()[:32]

def check_event(ev):
    """v2 event shape -> None, or the reason it is refused."""
    if ev.get("kind") != KIND: return "wrong kind"
    tags = ev.get("tags", [])
    if len(tags) != 1 or tags[0][0] != "z" or len(tags[0]) != 2: return "exactly one z tag and no other tags"
    if not HEX32.match(tags[0][1]): return "z tag is not 32 lowercase hex"
    c = ev.get("content", "")
    if not c.startswith("-----BEGIN PGP MESSAGE-----"): return "content must be only an armored PGP message"
    try:
        headers, ids = message_recipients(c)
    except ValueError as e:
        return f"bad PGP message: {e}"
    if headers: return "armor headers not allowed"
    if not ids or any(i != WILDCARD for i in ids): return "recipient key id must be the wildcard"
    return None

def check_pubkeys_fresh(events):
    keys = [e["pubkey"] for e in events]
    return len(keys) == len(set(keys))

def check_invite(inv):
    """v2 out-of-band invite -> None, or the reason it is refused."""
    if inv.get("ver") != 2: return "ver must be 2"
    for k in ("name", "pubKey", "fp", "intro"):
        if not isinstance(inv.get(k), str) or not inv[k]: return f"missing {k}"
    if re.search(r"[\x00-\x1f\x7f]", inv["name"]) or len(inv["name"]) > 64: return "bad name"
    if not FPR.match(inv["fp"]): return "fp must be the full fingerprint"
    if not HEX64.match(inv["intro"]): return "intro must be 64 lowercase hex"
    try:
        info = key_info(inv["pubKey"])
    except ValueError as e:
        return f"bad pubKey: {e}"
    if info["fingerprint"] != inv["fp"]: return "fp does not match pubKey"
    return None

MAX_AGE = 30 * 86400      # oldest send time a receiver accepts (its subscription window)
MAX_FUTURE = 600          # newest: 10 minutes ahead of the receiver's clock

def receive(case):
    """Receive decision for a decrypted, signature-checked inner payload. The OpenPGP
    signature check is abstracted as `signer` (fingerprint of the key that signed, or None).
    case: {inner, signer, own, tag, created_at, now, contacts:{fp: {chan_in}}, intro:[hex], seen:[ids]}
    -> 'accept' (message / rekey from a contact), 'accept: channel only' (hello from a
    contact: new channel secret, key and name unchanged), 'request' (hello from a new
    key: a contact request the user must approve), or 'reject: <reason>'."""
    p, own = case.get("inner"), case.get("own")
    if not isinstance(p, dict): return "reject: payload is not an object"
    isint = lambda x: isinstance(x, int) and not isinstance(x, bool)
    if not isint(p.get("ts")): return "reject: ts is not an integer"
    if not isint(case.get("created_at")) or not isint(case.get("now")): return "reject: bad times"
    if not all(isinstance(p.get(k), str) for k in ("v", "type", "id", "from", "to")): return "reject: missing field"
    if not isinstance(own, str) or not isinstance(case.get("tag"), str): return "reject: bad case"
    if p.get("v") != "nkip06/2": return "reject: unknown version"
    if p.get("type") not in ("msg", "hello", "rekey"): return "reject: unknown type"
    if not HEX32.match(p.get("id", "")): return "reject: bad id"
    if not case.get("signer"): return "reject: unsigned"
    if case["signer"] != p.get("from"): return "reject: signer is not from"
    if p.get("to") != own: return "reject: not addressed to us"
    # created_at is chosen by whoever holds the throwaway Nostr key; ts is signed by the
    # sender's PGP key. ts is the only send time; created_at must equal it (it picks the tag).
    if p.get("ts") != case["created_at"]: return "reject: ts differs from created_at"
    if p["ts"] < case["now"] - MAX_AGE: return "reject: too old"
    if p["ts"] > case["now"] + MAX_FUTURE: return "reject: from the future"
    # Replay protection is by the signed inner id only: a new id with the same body is a
    # new message (idempotence, not content dedupe).
    if p["id"] in case.get("seen", []): return "reject: replay"
    contacts = case.get("contacts", {})
    if p["type"] == "hello":
        if not any(channel_tag(s, case["created_at"]) == case["tag"] for s in case.get("intro", [])):
            return "reject: hello not on an intro channel"
        body = p.get("body") or {}
        try:
            key_fp = key_info(body.get("pubKey", ""))["fingerprint"]
        except (ValueError, KeyError, IndexError):
            return "reject: hello key unreadable"
        if key_fp != p["from"]: return "reject: hello key is not the signer"
        if not HEX64.match(body.get("chan", "")): return "reject: hello without chan"
        # A new key is always a new contact, whatever name it claims (a contact's key
        # change included); a known key only refreshes its channel.
        return "accept: channel only" if p["from"] in contacts else "request"
    c = contacts.get(p["from"])
    if not c: return "reject: unknown sender"
    if channel_tag(c["chan_in"], case["created_at"]) != case["tag"]: return "reject: tag is not this contact's channel"
    if p["type"] == "rekey" and not HEX64.match((p.get("body") or {}).get("chan", "")): return "reject: rekey without chan"
    return "accept"

# ── vectors ──────────────────────────────────────────────────────────────────
def check(path):
    d = json.load(open(path))
    keys = {n: key_info(k["public"]) for n, k in d["test_keys"].items()}
    for n, k in d["test_keys"].items():
        assert keys[n]["fingerprint"] == k["fingerprint"], n + ": fingerprint"
    for v in d["v1_observer"]:
        o = v1_observe(v["event"])
        who = keys[v["recipient"]]
        assert o["topic_fp8"] == o["header_fp8"] == who["fingerprint"][-8:], v["name"] + ": FP8 in tag and header"
        assert o["recipient_key_ids"] and all(i in who["subkey_ids"] for i in o["recipient_key_ids"]), v["name"] + ": PKESK names the recipient subkey"
        assert o == v["observed"], v["name"] + ": observed values"
    for v in d["v2_tags"]:
        assert epoch(v["created_at"]) == v["epoch"], "epoch"
        assert channel_tag(v["chan"], v["created_at"]) == v["tag"], f"tag {v['created_at']}"
    for g in d["v2_same_day"]:
        same = {channel_tag(g["chan"], t) for t in g["same_day"]}
        assert len(same) == 1 and same == {g["tag"]}, f"{g['name']}: same day, same tag"
        assert channel_tag(g["chan"], g["next_day"]) == g["next_tag"] != g["tag"], f"{g['name']}: next day, new tag"
    for v in d["v2_events"].get("valid_extra", []):
        assert check_event(v["event"]) is None, v["name"] + ": " + str(check_event(v["event"]))
    ex = d["v2_example"]
    assert check_event(ex["event"]) is None, "example event: " + str(check_event(ex["event"]))
    assert channel_tag(ex["chan"], ex["event"]["created_at"]) == ex["event"]["tags"][0][1], "example tag"
    assert len(ex["inner_plaintext"].encode()) % 256 == 0, "example padding"
    assert json.loads(ex["inner_plaintext"])["to"] == keys[ex["recipient"]]["fingerprint"], "example to"
    for v in d["v2_events"]["invalid"]:
        assert check_event(v["event"]) is not None and v["reason"] in check_event(v["event"]), f"{v['name']}: got {check_event(v['event'])}"
    assert not check_pubkeys_fresh(d["v2_events"]["reused_pubkey"]), "reused pubkey"
    for v in d["invites"]["valid"]:
        assert check_invite(v["invite"]) is None, v["name"] + ": " + str(check_invite(v["invite"]))
    for v in d["invites"]["invalid"]:
        r = check_invite(v["invite"])
        assert r is not None and v["reason"] in r, f"{v['name']}: got {r}"
    for v in d["receive"]:
        r = receive(v["case"])
        assert r == v["expect"], f"{v['name']}: got '{r}', expected '{v['expect']}'"
    print(f"ok: {len(d['v1_observer'])} v1 observations, {len(d['v2_tags'])} tags, {len(d['v2_same_day'])} same-day groups, 1 example, "
          f"{len(d['v2_events']['invalid'])} invalid events, {len(d['invites']['valid']) + len(d['invites']['invalid'])} invites, {len(d['receive'])} receive cases")

if __name__ == "__main__":
    if sys.argv[1:2] == ["check"]: check(sys.argv[2])
    else: print(__doc__)
