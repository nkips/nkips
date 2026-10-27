# No-KYC Improvement Proposals (NKIPs)

Open, vendor-neutral proposals for making no-KYC crypto swaps verifiable for
their users, from swaps to tips. Anyone (exchanges, aggregators, directories, wallet and
extension authors) can propose, review and implement.

| # | Title | Status |
| --- | --- | --- |
| [0001](nkips/nkip-0001.md) | Verifiable Deposit Receipts | Draft |
| [0002](nkips/nkip-0002.md) | Verifiable Monero Tips on Nostr | Draft |
| [0003](nkips/nkip-0003.md) | Sign-In with Monero | Draft |
| [0004](nkips/nkip-0004.md) | Signed JSON Objects over Nostr Events | Draft |
| [0005](nkips/nkip-0005.md) | Cashtags on Nostr | Draft |
| [0006](nkips/nkip-0006.md) | PGP Chat over Nostr | Draft |

## About

NKIPs grew out of the authors' work on kyc.rip, xmr.club and Ripley Terminal. They're
open to everyone, and no NKIP depends on those services: every role can be run
by anyone, and a proposal becomes Final only with two independent
implementations. Each NKIP lists known implementations, with the authors' own
projects marked.

## Related standards

- [XMR402](https://xmr402.org): an open protocol for paying for HTTP requests and other network resources in Monero.

## Discussion

Open an issue for questions, objections or implementation reports on any NKIP. Security problems in a spec can be reported the same way; there is no private code here to protect.

## Process

1. Open an issue describing the problem first.
2. Send a PR adding `nkips/nkip-XXXX.md` with the header block used in NKIP-0001. Numbers are assigned by maintainers.
3. Status moves Draft → Proposed (one reference implementation) → Final (two independent implementations). Final specs only get errata; changes go in a new NKIP.
4. Each Standards Track NKIP ships a schema and test vectors, checked in CI.

## Site

`python3 tools/build_site.py` builds nkips.org into `dist/`; `npx wrangler deploy` publishes it (Worker static assets).

## Tools

`python3 tools/nkip0001.py check nkips/nkip-0001/vectors/v1.json` checks the NKIP-0001 vectors (needs `pynacl`).
`python3 tools/nkip0003.py check nkips/nkip-0003/vectors/v1.json` checks the NKIP-0003 vectors (needs `pycryptodome`).
`python3 tools/nkip0004.py check nkips/nkip-0004/vectors/v1.json`, `tools/nkip0005.py` and `tools/nkip0006.py` check theirs the same way (standard library only).

## License

Specs and vectors: CC0-1.0. Code in `tools/`: MIT.
