#!/usr/bin/env node
//
// Independently verify an erasable-anchor proof.
//
//   verify-anchor <record-id> [--host https://recruiterlog.com]
//   verify-anchor --proof ./proof.json          verify a saved proof, no network
//   verify-anchor <record-id> --json            machine readable output
//
// Zero dependencies: Node's built-in crypto and fetch, nothing else. Copy this
// single file anywhere and it runs.
//
// The point is that it does NOT trust the party serving the proof. It asks for
// the record's data and its Merkle proof, then recomputes every hash here, and
// reads the published root straight off a public Solana RPC node. If a record
// was altered after anchoring, or a proof was fabricated, the comparison at
// the end fails.
//
// This is deliberately a separate implementation from both the erasable-anchor
// package and src/browser.mjs. If it imported either it would agree with it by
// construction and prove nothing. The three are held in agreement by the
// conformance suite in test/, against the fixed vectors published with the
// spec.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const DEFAULT_RPC = {
  devnet: "https://api.devnet.solana.com",
  "mainnet-beta": "https://api.mainnet-beta.solana.com",
  mainnet: "https://api.mainnet-beta.solana.com",
};

// --- the hashing rules, reimplemented from SPEC.md, not imported -----------

export function canonicalJson(value) {
  if (value === null || value === undefined) return "null";
  const t = typeof value;
  if (t === "boolean" || t === "string") return JSON.stringify(value);
  if (t === "number") {
    if (!Number.isFinite(value)) throw new Error("NaN/Infinity not representable");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (t === "object") {
    const keys = Object.keys(value).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(",")}}`;
  }
  throw new Error(`unsupported type ${t}`);
}

const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");

export function buildLeaf(facts, salt) {
  if (facts === null || typeof facts !== "object" || Array.isArray(facts)) {
    throw new Error("buildLeaf: facts must be a plain object");
  }
  if (Object.prototype.hasOwnProperty.call(facts, "salt")) {
    throw new Error('buildLeaf: facts must not contain a "salt" key');
  }
  if (typeof salt !== "string" || salt.length === 0) {
    throw new Error("buildLeaf: salt must be a non-empty string");
  }
  return sha256(
    Buffer.concat([Buffer.from([0x00]), Buffer.from(canonicalJson({ ...facts, salt }), "utf8")])
  );
}

export const hashPair = (left, right) =>
  sha256(Buffer.concat([Buffer.from([0x01]), Buffer.from(left, "hex"), Buffer.from(right, "hex")]));

export function walkProof(leaf, proof) {
  let acc = leaf;
  for (const step of proof) {
    if (step.position !== "left" && step.position !== "right") {
      throw new Error(`walkProof: unknown position ${JSON.stringify(step.position)}`);
    }
    acc = step.position === "left" ? hashPair(step.hash, acc) : hashPair(acc, step.hash);
  }
  return acc;
}

export function parseMemo(memo, expectedPrefix) {
  const prefixPart = expectedPrefix
    ? expectedPrefix.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
    : "[a-z0-9]{1,16}";
  const m = String(memo).match(new RegExp(`^(${prefixPart}):v(\\d+):([0-9-]+):([0-9a-f]{64})$`));
  if (!m) return null;
  return { prefix: m[1], version: Number(m[2]), period: m[3], root: m[4] };
}

// --- read the root back off the chain --------------------------------------

export async function readOnChainMemo(signature, endpoint) {
  const res = await fetch(endpoint, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "getTransaction",
      params: [
        signature,
        { commitment: "confirmed", encoding: "json", maxSupportedTransactionVersion: 0 },
      ],
    }),
  });

  const json = await res.json();
  if (json.error) throw new Error(`RPC error: ${json.error.message}`);
  if (!json.result) return null;

  for (const line of json.result.meta?.logMessages || []) {
    const m = line.match(/Memo \(len \d+\): "(.*)"$/);
    if (m) return { memo: m[1], blockTime: json.result.blockTime };
  }
  return null;
}

// --- run -------------------------------------------------------------------

const USAGE = `usage:
  verify-anchor <record-id> [options]
  verify-anchor --proof <file> [options]

options:
  --host <url>      where to fetch the proof from (default https://recruiterlog.com)
  --path <tmpl>     proof path template, {id} is substituted
                    (default /api/ledger/proof/{id})
  --proof <file>    verify a saved proof document instead of fetching one
  --prefix <str>    expected memo prefix (default rl)
  --rpc <url>       RPC endpoint, overriding the proof's cluster
  --no-chain        skip the on chain check, verifying the proof's maths only
  --json            emit a JSON result instead of prose
  -h, --help        this message

exit codes: 0 verified, 1 failed, 2 usage error`;

function parseArgs(argv) {
  const opts = {
    host: "https://recruiterlog.com",
    path: "/api/ledger/proof/{id}",
    prefix: "rl",
    json: false,
    chain: true,
  };
  const positional = [];

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const needsValue = (name) => {
      const v = argv[++i];
      // Catching this here rather than letting `undefined` flow onward: a
      // missing value otherwise turns into a fetch of "undefined" and a
      // confusing 404 several steps later.
      if (v === undefined || v.startsWith("--")) {
        throw new Error(`${name} requires a value`);
      }
      return v;
    };

    if (a === "-h" || a === "--help") return { help: true };
    else if (a === "--host") opts.host = needsValue("--host").replace(/\/+$/, "");
    else if (a === "--path") opts.path = needsValue("--path");
    else if (a === "--proof") opts.proofFile = needsValue("--proof");
    else if (a === "--prefix") opts.prefix = needsValue("--prefix");
    else if (a === "--rpc") opts.rpc = needsValue("--rpc");
    else if (a === "--no-chain") opts.chain = false;
    else if (a === "--json") opts.json = true;
    else if (a.startsWith("-")) throw new Error(`unknown option ${a}`);
    else positional.push(a);
  }

  if (positional.length > 1) throw new Error("expected at most one record id");
  opts.recordId = positional[0];
  return opts;
}

async function main(argv) {
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (err) {
    console.error(`error: ${err.message}\n\n${USAGE}`);
    return 2;
  }
  if (opts.help) {
    console.log(USAGE);
    return 0;
  }
  if (!opts.recordId && !opts.proofFile) {
    console.error(`error: give a record id, or --proof <file>\n\n${USAGE}`);
    return 2;
  }

  const out = [];
  const checks = [];
  const say = (s) => {
    if (!opts.json) console.log(s);
    out.push(s);
  };
  const check = (ok, label, detail) => {
    checks.push({ ok, label, detail });
    if (!opts.json) console.log(`   ${ok ? "OK  " : "FAIL"}  ${label}`);
  };

  // 1. Obtain the proof
  let p;
  if (opts.proofFile) {
    say(`Reading proof from ${opts.proofFile}`);
    try {
      p = JSON.parse(readFileSync(opts.proofFile, "utf8"));
    } catch (err) {
      console.error(`error: could not read proof: ${err.message}`);
      return 2;
    }
  } else {
    const url = opts.host + opts.path.replace("{id}", encodeURIComponent(opts.recordId));
    say(`Verifying record ${opts.recordId}`);
    say(`Proof source: ${url}  (data only, every hash is recomputed here)`);
    let res;
    try {
      res = await fetch(url);
    } catch (err) {
      console.error(`error: could not reach ${url}: ${err.message}`);
      return 1;
    }
    if (!res.ok) {
      // A 404 is the publisher saying "no such record", which is a different
      // situation from a server fault and deserves a different sentence. Left
      // as an exit 1 either way: the caller asked about a record and did not
      // get an answer about it.
      const body = await res.json().catch(() => null);
      if (res.status === 404) {
        console.error(
          `error: no record with id ${opts.recordId}.` +
            (body?.detail ? ` ${body.detail}` : "") +
            "\n       Check the id. Ids come from the publisher's ledger listing."
        );
      } else {
        console.error(`error: proof endpoint returned ${res.status}`);
      }
      return 1;
    }
    p = await res.json();
  }

  if (p.anchored === false) {
    // Each reason means something different to whoever is standing here, so
    // say which. "Not anchored" covering four situations is how people end up
    // waiting for something that will never happen.
    const REASONS = {
      not_yet_anchored:
        "This record is not anchored yet. Records anchor on the next daily run\n" +
        "   after they settle, so a recent one is expected to look like this.",
      batch_pending:
        "This record's leaf is frozen, but the batch it belongs to has not been\n" +
        "   confirmed on chain yet. Try again after the next run.",
      unknown_record: "No record has that id. Check the id.",
      not_configured: "The publisher has not configured anchoring, so there is nothing to check.",
    };
    say(REASONS[p.reason] || `This record is not anchored${p.reason ? ` (${p.reason})` : ""}.`);
    if (opts.json) console.log(JSON.stringify({ anchored: false, reason: p.reason ?? null }, null, 2));
    // Exit 0: "not anchored yet" is a correct answer to the question, not a
    // failure of verification. Only a record that fails to verify is exit 1.
    return p.reason === "unknown_record" ? 1 : 0;
  }

  const facts = p.facts ?? p.snapshot;
  say(`period ${p.period ?? "?"} · cluster ${p.cluster ?? "?"} · ${p.leafCount ?? "?"} records in this batch`);

  // 2. Recompute the leaf
  say("\nRecompute the leaf from the record's own data");
  let leaf;
  try {
    leaf = buildLeaf(facts, p.salt);
  } catch (err) {
    check(false, `could not recompute the leaf: ${err.message}`);
    if (opts.json) console.log(JSON.stringify({ verified: false, checks }, null, 2));
    return 1;
  }
  say(`   computed  ${leaf}`);
  say(`   published ${p.leafHash}`);
  check(leaf === p.leafHash, "the record's content still hashes to its published leaf", leaf);

  // 3. Walk the proof
  say("\nWalk the Merkle proof up to the root");
  const steps = p.proof || [];
  say(`   ${steps.length} sibling hash(es) from leaf to root`);
  let computedRoot;
  try {
    computedRoot = walkProof(leaf, steps);
  } catch (err) {
    check(false, `could not walk the proof: ${err.message}`);
    if (opts.json) console.log(JSON.stringify({ verified: false, checks }, null, 2));
    return 1;
  }
  say(`   computed  ${computedRoot}`);
  say(`   claimed   ${p.merkleRoot}`);
  check(computedRoot === p.merkleRoot, "the leaf is genuinely part of the claimed tree", computedRoot);

  // 4. Read the root off the chain
  const endpoint = opts.rpc || DEFAULT_RPC[p.cluster];
  if (!opts.chain) {
    say("\nSkipping the on chain check (--no-chain).");
    say("   Without it this shows the proof is internally consistent, and nothing");
    say("   about what was actually published.");
  } else if (!p.txSignature) {
    check(false, "the proof carries no transaction signature to check");
  } else if (!endpoint) {
    check(false, `no RPC endpoint known for cluster ${JSON.stringify(p.cluster)}, pass --rpc`);
  } else {
    say(`\nRead the root back off the chain (not from the proof's source)`);
    say(`   ${endpoint}`);
    say(`   tx ${p.txSignature}`);
    let onChain;
    try {
      onChain = await readOnChainMemo(p.txSignature, endpoint);
    } catch (err) {
      check(false, `RPC call failed: ${err.message}`);
      onChain = null;
    }
    if (!onChain) {
      check(false, "no memo found in that transaction");
    } else {
      say(`   memo: ${onChain.memo}`);
      const parsed = parseMemo(onChain.memo, opts.prefix);
      check(!!parsed, `the on-chain memo is a well formed ${opts.prefix} anchor`);
      if (parsed) {
        check(parsed.root === computedRoot, "the root we computed is the root published on chain", parsed.root);
        if (p.period) check(parsed.period === p.period, `the on-chain period matches (${parsed.period})`);
        if (onChain.blockTime) {
          say(`   published at ${new Date(onChain.blockTime * 1000).toISOString()}`);
        }
      }
    }
  }

  const failed = checks.some((c) => !c.ok);

  if (opts.json) {
    console.log(JSON.stringify({ verified: !failed, checks }, null, 2));
    return failed ? 1 : 0;
  }

  console.log("\n" + "-".repeat(70));
  if (failed) {
    console.log("VERIFICATION FAILED. This record does not match what was published.");
    return 1;
  }
  console.log("VERIFIED. This record is unchanged since it was anchored.");
  console.log("\nProven: this exact content was in a tree whose root was published on chain.");
  console.log("Not proven: that no records were withheld from that batch. Anchoring shows");
  console.log("nothing was altered after the fact; it cannot show the set was complete.");
  return 0;
}

// Run only when invoked directly, so the hashing functions above can be
// imported and cross-checked against another implementation.
if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  // Set the code and let the process wind down, rather than calling
  // process.exit().
  //
  // process.exit() tears down while libuv still has handles closing, and on
  // Windows that aborts with "Assertion failed: !(handle->flags &
  // UV_HANDLE_CLOSING)" AFTER the verdict has already printed, replacing the
  // exit code with 0xC0000409. The output looks right and the exit code is
  // meaningless, which is the worst combination for a tool whose entire
  // interface in CI is its exit code.
  //
  // fetch keeps a pooled connection alive, which would hold the loop open, so
  // the timer is the backstop: unref'd so it never delays a clean exit, and
  // if anything is still lingering a moment later we leave anyway.
  process.exitCode = await main(process.argv.slice(2));
  setTimeout(() => process.exit(process.exitCode), 250).unref();
}
