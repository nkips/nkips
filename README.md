# No-KYC Improvement Proposals (NKIPs)

Open, vendor-neutral proposals for making no-KYC crypto swaps verifiable for
their users. Anyone (exchanges, aggregators, directories, wallet and
extension authors) can propose, review and implement.

| # | Title | Status |
| --- | --- | --- |
| [0001](nkips/nkip-0001.md) | Verifiable Deposit Receipts | Draft |

## Process

1. Open an issue describing the problem first.
2. Send a PR adding `nkips/nkip-XXXX.md` with the header block used in NKIP-0001. Numbers are assigned by maintainers.
3. Status moves Draft → Proposed (one reference implementation) → Final (two independent implementations). Final specs only get errata; changes go in a new NKIP.
4. Each Standards Track NKIP ships a schema and test vectors, checked in CI.

## Tools

`python3 tools/nkip0001.py check nkips/nkip-0001/vectors/v1.json` checks the NKIP-0001 vectors (needs `pynacl`).

## License

Specs and vectors: CC0-1.0. Code in `tools/`: MIT.
