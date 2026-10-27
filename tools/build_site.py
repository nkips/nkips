#!/usr/bin/env python3
"""Build the static nkips.org site into dist/. Usage: python3 tools/build_site.py"""
import html, json, re, shutil
from pathlib import Path
import markdown

ROOT = Path(__file__).resolve().parent.parent
SRC, DIST = ROOT / "nkips", ROOT / "dist"
CSS = (ROOT / "site" / "style.css").read_text()

def page(title, body, desc, path, og="index"):
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title>
<meta name="description" content="{html.escape(desc)}">
<link rel="canonical" href="https://nkips.org{path}">
<meta property="og:type" content="article">
<meta property="og:site_name" content="NKIPs">
<meta property="og:title" content="{html.escape(title)}">
<meta property="og:description" content="{html.escape(desc)}">
<meta property="og:url" content="https://nkips.org{path}">
<meta property="og:image" content="https://nkips.org/og/{og}.png">
<meta property="og:image:width" content="1200"><meta property="og:image:height" content="630">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:image" content="https://nkips.org/og/{og}.png">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='4' fill='%23f6efd9'/%3E%3Ctext x='16' y='22' font-family='Georgia,serif' font-size='16' text-anchor='middle' fill='%232b2418'%3EN%3C/text%3E%3C/svg%3E">
<style>{CSS}</style></head>
<body><header class="mast"><a class="brand" href="/">NKIPs</a><nav><a href="/">Proposals</a><a href="/process/">Process</a><a href="https://github.com/nkips/nkips">Source</a></nav></header>
<main>{body}</main>
<footer><p>NKIPs are dedicated to the public domain (CC0). Anyone may implement them without permission. Discuss or propose changes on <a href="https://github.com/nkips/nkips/issues">GitHub</a>.</p></footer>
</body></html>"""

def parse_preamble(md):
    m = re.match(r"```\n(.*?)\n```\n", md, re.S)
    meta = dict(l.split(": ", 1) for l in m.group(1).splitlines()) if m else {}
    return meta, md[m.end():] if m else md

def render(md):
    conv = markdown.Markdown(extensions=["tables", "fenced_code", "toc", "sane_lists"],
                             extension_configs={"toc": {"toc_depth": "2-3", "permalink": False}})
    out = conv.convert(md)
    out = out.replace("<li>[ ] ", '<li class="task">')
    return out, conv.toc

def build():
    if DIST.exists(): shutil.rmtree(DIST)
    DIST.mkdir()
    rows = []
    for f in sorted(SRC.glob("nkip-*.md")):
        slug = f.stem
        meta, md = parse_preamble(f.read_text())
        md = re.sub(r"^# .*\n", "", md, count=1, flags=re.M)
        md = md.replace(f"]({slug}/", "](")
        lead, rest = md.strip().split("\n\n", 1)
        body_html, toc = render(rest)
        num = int(meta.get("NKIP", "0"))
        title = meta.get("Title", slug)
        pre = "".join(f"<tr><th>{html.escape(k)}</th><td>{html.escape(v)}</td></tr>" for k, v in meta.items())
        files = ""
        if (SRC / slug).is_dir():
            shutil.copytree(SRC / slug, DIST / slug)
            links = sorted(p.relative_to(SRC / slug).as_posix() for p in (SRC / slug).rglob("*") if p.is_file())
            files = "<p class='files'>Files: " + " · ".join(f'<a href="{l}">{l}</a>' for l in links) + "</p>"
        else:
            (DIST / slug).mkdir()
        (DIST / slug / "index.md").write_text(f.read_text())
        art = f"""<article class="paper">
<p class="kicker">NKIP-{num:04d} · {html.escape(meta.get('Status',''))}</p>
<h1>{html.escape(title)}</h1>
<p class="abstract"><span>Abstract.</span> {render(lead)[0][3:-4]}</p>
<table class="preamble">{pre}</table>
{files}
<details class="toc" open><summary>Contents</summary>{toc}</details>
<div class="numbered">{body_html}</div>
<p class="source"><a href="index.md">Markdown source</a> · <a href="https://github.com/nkips/nkips/blob/main/nkips/{slug}.md">History</a> · <a href="https://github.com/nkips/nkips/issues/new?title={slug}%3A%20">Comment</a></p>
</article>"""
        (DIST / slug / "index.html").write_text(page(f"NKIP-{num:04d}: {title}", art, re.sub('<[^>]+>', '', render(lead)[0])[:200], f"/{slug}/", og=slug))
        rows.append(f'<tr><td class="n"><a href="/{slug}/">{num:04d}</a></td><td><a href="/{slug}/">{html.escape(title)}</a></td><td>{html.escape(meta.get("Type",""))}</td><td><span class="status s-{meta.get("Status","").lower()}">{html.escape(meta.get("Status",""))}</span></td><td>{html.escape(meta.get("Created",""))}</td></tr>')
    index = f"""<section class="hero"><h1>No-KYC Improvement Proposals</h1>
<p class="lede">Open standards that let users of no-KYC swaps, services and tips check what they were promised, without trusting the operator and without giving up their privacy.</p>
<p>Anyone can propose, review or implement an NKIP: exchanges, aggregators, directories, wallet and extension authors. Proposals are vendor-neutral, ship with schemas and test vectors, and are dedicated to the public domain.</p></section>
<h2 class="sec">Proposals</h2>
<table class="index"><thead><tr><th>#</th><th>Title</th><th>Type</th><th>Status</th><th>Created</th></tr></thead><tbody>{''.join(rows)}</tbody></table>
<h2 class="sec">Principles</h2>
<ol class="principles"><li><b>Verifiable, not trusted.</b> A claim counts when it can be checked from signatures and public chains.</li>
<li><b>Private by construction.</b> Public records hold hashes, never plaintext addresses or amounts.</li>
<li><b>No gatekeeper.</b> No NKIP requires one company's server; every role can be run by anyone.</li>
<li><b>No KYC, ever.</b> No NKIP asks either party to identify themselves.</li></ol>
<h2 class="sec">About</h2>
<p>NKIPs grew out of the authors' work on kyc.rip, xmr.club and Ripley Terminal. They're open to everyone, and no NKIP depends on those services: every role can be run by anyone, and a proposal becomes Final only with two independent implementations. Each NKIP lists known implementations, with the authors' own projects marked.</p>
<h2 class="sec">Related standards</h2>
<ul><li><a href="https://xmr402.org">XMR402</a>: an open protocol for paying for HTTP requests and other network resources in Monero.</li></ul>"""
    (DIST / "index.html").write_text(page("NKIPs: No-KYC Improvement Proposals", index, "Open, vendor-neutral standards for verifiable no-KYC swaps, services and tips.", "/"))
    proc_md = (ROOT / "README.md").read_text().split("## Process", 1)[1].split("## Tools", 1)[0]
    (DIST / "process").mkdir()
    (DIST / "process" / "index.html").write_text(page("Process · NKIPs", f'<article class="paper"><h1>Process</h1>{render(proc_md)[0]}<h2>Statuses</h2><table><tr><th>Draft</th><td>Open for comment; anything can change.</td></tr><tr><th>Proposed</th><td>One reference implementation exists.</td></tr><tr><th>Final</th><td>Two independent implementations interoperate. Errata only.</td></tr><tr><th>Withdrawn</th><td>Abandoned by its authors.</td></tr></table></article>', "How NKIPs are proposed, reviewed and finalised.", "/process/"))
    shutil.copy(ROOT / "site" / "404.html", DIST / "404.html")
    shutil.copytree(ROOT / "site" / "og", DIST / "og")
    (DIST / "robots.txt").write_text("User-agent: *\nAllow: /\nSitemap: https://nkips.org/sitemap.xml\n")
    urls = ["/", "/process/"] + [f"/{f.stem}/" for f in sorted(SRC.glob('nkip-*.md'))]
    (DIST / "sitemap.xml").write_text('<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' + "".join(f"<url><loc>https://nkips.org{u}</loc></url>" for u in urls) + "</urlset>")
    (DIST / "_headers").write_text("/*\n  X-Content-Type-Options: nosniff\n  Referrer-Policy: no-referrer\n  Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\n/*.json\n  Access-Control-Allow-Origin: *\n")
    print("built", len(urls), "pages")

if __name__ == "__main__": build()
