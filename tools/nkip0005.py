#!/usr/bin/env python3
"""NKIP-0005 reference helpers: `$TICKER` tokenizing, the `cashtag` tag, asset ids.
Checks the vectors: python3 tools/nkip0005.py check nkips/nkip-0005/vectors/v1.json
Standard library only."""
import json, re, sys, unicodedata

TICKER = re.compile(r"^[A-Z]{2,6}$")
# Spans that never hold cashtags: fenced code, inline code, URLs, nostr: entities.
SKIP = re.compile(r"```.*?(?:```|\Z)|`[^`\n]+`|https?://\S+|nostr:[a-z0-9]+", re.S)
# Short ids, exactly the spec grammar. Step 1 is the shape; step 2 (asset_info) looks
# the chain slug up in CHAINS, so a well-shaped id on an unlisted chain is still ignored.
SHORT_KIND = re.compile(r"^([a-z0-9]{1,16}):(native|equity)$")
SHORT_TOKEN = re.compile(r"^([a-z0-9]{1,16}):([a-z0-9]{1,16}):([A-Za-z0-9]{1,128})$")
SEARCH_CAP = 10
CAIP19 = re.compile(r"^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}/[-a-z0-9]{3,8}:[-.%a-zA-Z0-9]{1,128}(/[-.%a-zA-Z0-9]{1,78})?$")
MODES = ("compact", "expanded")

# Normative mapping tables (NKIP-0005 §Asset ids). Additions only via the changelog.
CHAINS = {
    "bitcoin": "bip122:000000000019d6689c085ae165831e93",
    "monero": "monero:418015bb9ae982a1975da7d79277c270",
    "ethereum": "eip155:1",
    "optimism": "eip155:10",
    "bsc": "eip155:56",
    "polygon": "eip155:137",
    "base": "eip155:8453",
    "arbitrum": "eip155:42161",
    "solana": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
}
TOKEN_NS = {"eip155": "erc20", "solana": "token"}
NATIVE = {
    "xmr": "monero:418015bb9ae982a1975da7d79277c270/slip44:128",
    "btc": "bip122:000000000019d6689c085ae165831e93/slip44:0",
    "eth": "eip155:1/slip44:60",
    "sol": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp/slip44:501",
}

def _word(ch):
    """Letters, combining marks and numbers of any script, and `_` (Unicode L*, M*, N*)."""
    return ch == "_" or unicodedata.category(ch)[0] in "LMN"

def cashtags(content):
    """Unique upper-cased tickers of `$TICKER` tokens in `content`, first-seen order."""
    # Skipped spans are blanked with a word character, so a `$` glued to one has no
    # left boundary either.
    text = SKIP.sub(lambda m: "_" * len(m.group(0)), content or "")
    out, i = [], 0
    while True:
        i = text.find("$", i)
        if i < 0: return out
        j = i + 1
        while j < len(text) and "A" <= text[j].upper() <= "Z" and text[j].isascii(): j += 1
        letters = text[i + 1:j]
        left_ok = i == 0 or not (_word(text[i - 1]) or text[i - 1] == "$")
        right_ok = j == len(text) or not _word(text[j])
        tk = letters.upper()
        if left_ok and right_ok and TICKER.match(tk) and tk not in out: out.append(tk)
        i = max(j, i + 1)

def asset_info(asset, ticker):
    """-> {'form', 'caip19'} for a usable asset id bound to `ticker`, else None (reader
    then resolves by ticker alone)."""
    if not isinstance(asset, str): return None
    if CAIP19.match(asset):
        return {"form": "caip19", "caip19": asset, "symbol_check": True}
    m = SHORT_KIND.match(asset)
    if m:
        if m.group(1) != ticker.lower(): return None             # ticker binding
        if m.group(2) == "native":
            if m.group(1) not in NATIVE: return None                # unlisted native id: ignored
            return {"form": "native", "caip19": NATIVE[m.group(1)], "symbol_check": False}
        return {"form": "equity", "caip19": None, "symbol_check": False}
    m = SHORT_TOKEN.match(asset)
    if not m or m.group(1) != ticker.lower(): return None
    chain, addr = m.group(2), m.group(3)
    if chain not in CHAINS: return None
    ns = CHAINS[chain].split(":")[0]
    if ns not in TOKEN_NS: return None
    return {"form": "token", "caip19": f"{CHAINS[chain]}/{TOKEN_NS[ns]}:{addr}", "symbol_check": True}

def embed(ev):
    """The note's cashtag attachment per NKIP-0005, or None."""
    tag = next((t for t in ev.get("tags", []) if isinstance(t, list) and t and t[0] == "cashtag"), None)
    if not tag or len(tag) < 2 or not isinstance(tag[1], str): return None
    tk = tag[1].strip().upper()
    if not TICKER.match(tk) or tk not in cashtags(ev.get("content", "")): return None
    mode = tag[2] if len(tag) > 2 and tag[2] in MODES else "compact"
    out = {"ticker": tk, "mode": mode, "asset": None}
    if len(tag) > 3:
        info = asset_info(tag[3], tk)
        if info: out["asset"] = dict(info, id=tag[3])
    return out

def search_tags(content):
    """The optional NIP-24 search tags a writer adds: one per distinct cashtag, `$` +
    lower-case ticker, first-seen order, at most SEARCH_CAP."""
    return [["t", "$" + tk.lower()] for tk in cashtags(content)[:SEARCH_CAP]]

def display(ev, resolver):
    """What the reader labels the attachment with. `resolver` maps CAIP-19 ids to the
    {symbol, name} a real reader would look up. A resolved symbol that differs from the
    ticker is shown as the asset's own name, never as $TICKER."""
    e = embed(ev)
    if not e: return None
    a = e["asset"]
    if not a or not a["symbol_check"]: return {"label": "$" + e["ticker"], "mismatch": False}
    r = resolver.get(a["caip19"])
    if not r: return {"label": "$" + e["ticker"], "mismatch": False, "unresolved": True}
    if r["symbol"].upper() == e["ticker"]: return {"label": "$" + e["ticker"], "mismatch": False}
    return {"label": f"{r['name']} ({r['symbol']})", "mismatch": True}

def check(path):
    d = json.load(open(path))
    for v in d["tokenize"]:
        got = cashtags(v["content"])
        assert got == v["cashtags"], f"tokenize {v['name']}: {got} != {v['cashtags']}"
    for v in d["events"]:
        got = embed(v["event"])
        assert got == v["embed"], f"event {v['name']}: {json.dumps(got)} != {json.dumps(v['embed'])}"
    for v in d["search"]:
        got = search_tags(v["content"])
        assert got == v["tags"], f"search {v['name']}: {got} != {v['tags']}"
    for v in d["display"]:
        got = display(v["event"], d["resolver"])
        assert got == v["display"], f"display {v['name']}: {got} != {v['display']}"
    print(f"ok: {len(d['tokenize'])} tokenize, {len(d['events'])} events, {len(d['search'])} search, {len(d['display'])} display")

if __name__ == "__main__":
    if sys.argv[1:2] == ["check"]: check(sys.argv[2])
    else: print(__doc__)
