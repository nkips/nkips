# Swap Improvement Proposals (working name)

Open, vendor-neutral proposals for making no-KYC crypto swaps verifiable for
their users. Anyone (exchanges, aggregators, directories, wallet and
extension authors) can propose, review and implement.

| # | Title | Status |
| --- | --- | --- |
| [0001](sips/sip-0001.md) | Verifiable Deposit Receipts | Draft |

## Process

1. Open an issue describing the problem first.
2. Send a PR adding `sips/sip-XXXX.md` with the header block used in SIP-0001. Numbers are assigned by maintainers.
3. Status moves Draft → Proposed (one reference implementation) → Final (two independent implementations). Final specs only get errata; changes go in a new SIP.
4. Each Standards Track SIP ships a schema and test vectors, checked in CI.

## Tools

`python3 tools/sip0001.py check sips/sip-0001/vectors/v1.json` checks the SIP-0001 vectors (needs `pynacl`).

## License

Specs and vectors: CC0-1.0. Code in `tools/`: MIT.
