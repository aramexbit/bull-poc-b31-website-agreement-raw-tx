# PoC for Bull.family bug bounty report B-31

## Website agreement page sends the server's transaction verbatim — a malicious server turns a "Vote yes" / Release / Refund click into an arbitrary payment

**Report B-31** (K-1011). Website chunk under test: `agreement-chunk.js` —
the `/agreement/:id` page chunk live 19 Nov 2026, sha256
`51522088765094a2186012fd8a7e0a5fbc0f7a745f5a5e97d908a9c308e32c3a`,
4,879 bytes (`https://www.bull.family/agreement/:id`, chunk
`page-c2f2b455b7bc6e38.js`).

### The bug

The agreement page fetches `GET /api/v1/agreements/:id` and sends the
transaction objects from that response **verbatim** to the wallet:

```js
async function x(e,t){
  let e = await m({to: t.to, data: t.data, value: BigInt(t.value||"0"), chainId: l.ob.id});
  ...
}
```

There is no check that `t.to` is the Bull Agreement contract
(`0x84C6D5dAf99BC65ed3A1D26Ca88ffa834D143999`), no check that `value` is 0,
and no check of `data`. The chunk contains the Agreement address **0
times**, the escrow constant **0 times**, and never reads `f.contract` /
`f.agreement` from the same response. Three buttons feed this single sink:
the condition actions ("Vote yes" / "Object" / "Confirm",
`conditions[].actions[]`), "Release payment to the payee"
(`f.releaseTransaction`), and "Refund the payer" (`f.refundTransaction`).

A compromised/malicious API server — the SDK's own stated threat model —
can therefore turn an innocent click into an arbitrary payment:

- "Vote yes" with `{to: attacker, data: "0x", value: 1 ETH}` — a vote is
  supposed to move 0 value (gas only), so the user has no reason to expect
  a payment at all.
- `releaseTransaction` with `{to: attacker, value: 0.5 ETH}`.
- An action with `{to: <token contract>, data: transfer(attacker, balance)}`
  — the destination looks like a legitimate token contract in the wallet
  prompt.

This is the same root cause as B-27 (`/d/` buyer flow) and B-30 (`/o/`
seller flow), but a different page, function, victim, and money flow;
pinning the escrow address in `/d/` and `/o/` cannot close this page. The
SDK itself pins destinations (`#guard` only allows AGREEMENT/ESCROWS with a
function allowlist) — the website simply has no equivalent guard.

### How to reproduce

Prerequisites: Node.js 20+, Foundry (`anvil` on PATH or at
`~/.foundry/bin/anvil`).

```sh
npm install
# start a fresh Anvil on port 8549, chain-id 4663 (a second terminal):
anvil --port 8549 --chain-id 4663
node run-poc.mjs   # prints the case table and writes poc-result-k1011.json
```

The runner replays the page's exact `sendTransaction({to, data, value})`
call against a mock API (`StubAgreement` + `MockERC20` in `chain/`,
throwaway Anvil keys, no real funds). Expected result:

| Case | Result |
|---|---|
| P1 malicious "Vote yes": `to`=attacker EOA, `value`=1 ETH | EXPLOITED — victim −1.0000 ETH, attacker +1.0000 ETH |
| P2 malicious `releaseTransaction`: `to`=attacker EOA, `value`=0.5 ETH | EXPLOITED — attacker +0.5000 ETH |
| P3 malicious action: `to`=token contract, `data`=`transfer(attacker, 1000)` | EXPLOITED — victim −1000 tokens, attacker +1000 |
| C0 honest vote: `to`=StubAgreement, `vote(1,0)`, value 0 | OK — vote recorded, victim loses only gas (~0.0001 ETH) |
| C1 honest release: `to`=StubAgreement, `release(1)`, value 0 | OK — released, payee +0.5000 ETH |

Result: **EXPLOITED 3/3, CONTROLS 2/2** (exit 0), reproduced on multiple
fresh Anvils with identical results. `poc-result-k1011.json` in this repo
is the output of the last verification run.

### Impact

Uncapped: the server chooses any `value` (up to the victim's whole ETH
balance) and any `data` (including ERC-20 drains). Every agreement
participant who clicks Vote / Release / Refund on the website is exposed.
Honest caveat: the wallet confirmation shows `to`/`value`, as in B-27/B-30
— the user must click the button first; the deception is that a "Vote yes"
button should never move funds.

### Suggested fix

Pin the destination in `x()` exactly like the SDK's `#guard`: require `t.to`
to equal the agreement's own contract address from the same response
(`f.contract` / `f.agreement`, or the hardcoded `0x84C6…`), require `value`
to be 0 for vote/object/attest actions, and allowlist the called function
(`vote` / `object` / `attest` / `release` / `refund`) for the matching
agreement id — the same pattern the `/o/` ghost flow `z()` already uses
(HI pin + on-chain `deals()` verification).
