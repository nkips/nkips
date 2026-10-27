#!/usr/bin/env python3
"""Render 1200x630 social cards into site/og/ (committed). Needs playwright.
Usage: python3 tools/og_cards.py"""
import html, re
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "site" / "og"

TPL = """<!doctype html><meta charset="utf-8"><style>
html,body{margin:0;width:1200px;height:630px;background:#e9dfc2}
.s{position:absolute;inset:34px 40px;background:#fbf6e6;border:1px solid #d9cba4;box-shadow:0 14px 40px -24px rgba(60,40,10,.6);padding:58px 70px;box-sizing:border-box;font-family:'Iowan Old Style','Palatino Linotype',Palatino,Georgia,serif;color:#2b2418}
.k{font-variant:small-caps;letter-spacing:.14em;color:#6f6350;font-size:26px}
h1{font-size:{fs}px;line-height:1.12;margin:18px 0 22px;font-weight:600}
p{font-size:28px;line-height:1.45;color:#4a3f2e;margin:0;max-width:960px}
.f{position:absolute;left:70px;right:70px;bottom:44px;display:flex;justify-content:space-between;border-top:1px solid #d9cba4;padding-top:16px;font-size:22px;color:#6f6350;font-variant:small-caps;letter-spacing:.06em}
.f b{color:#8a3b12;font-weight:600}
</style><div class="s"><div class="k">{kicker}</div><h1>{title}</h1><p>{lede}</p>
<div class="f"><span><b>nkips.org</b> · No-KYC Improvement Proposals</span><span>CC0 · open to all</span></div></div>"""

def cards():
    yield "index", "Open standards", "No-KYC Improvement Proposals", "Standards that let users of no-KYC swaps, services and tips check what they were promised, without trusting the operator and without giving up their privacy."
    for f in sorted((ROOT / "nkips").glob("nkip-*.md")):
        md = f.read_text()
        meta = dict(l.split(": ", 1) for l in re.match(r"```\n(.*?)\n```", md, re.S).group(1).splitlines())
        body = re.sub(r"^```.*?```\n+# .*?\n+", "", md, count=1, flags=re.S)
        lede = body.split("\n\n", 1)[0].replace("\n", " ")
        lede = re.sub(r"`([^`]*)`", r"\1", lede)
        yield f.stem, f"NKIP-{int(meta['NKIP']):04d} · {meta['Status']}", meta["Title"], lede

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        b = p.chromium.launch()
        pg = b.new_page(viewport={"width": 1200, "height": 630})
        for name, kicker, title, lede in cards():
            fs = 70 if len(title) < 30 else 60
            pg.set_content(TPL.replace("{fs}", str(fs)).replace("{kicker}", html.escape(kicker)).replace("{title}", html.escape(title)).replace("{lede}", html.escape(lede)))
            pg.screenshot(path=str(OUT / f"{name}.png"))
            print("card", name)
        b.close()

if __name__ == "__main__": main()
