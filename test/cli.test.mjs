// The CLI at its actual surface: spawned as a process, given files and flags,
// checked on stdout and exit code.
//
// Importing its functions and asserting on return values, which the other test
// files do, says nothing about whether the tool works. Exit codes in particular
// are the whole interface for anyone wiring this into CI, and they are easy to
// get wrong in a way no unit test notices.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import * as browser from "../src/browser.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, "..", "bin", "verify-anchor.mjs");
const tmp = mkdtempSync(join(tmpdir(), "erasable-anchor-verify-"));

const run = (...args) =>
  spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8", timeout: 30000 });

/**
 * A proof document, built with the BROWSER implementation so that the CLI is
 * verifying something it did not produce.
 */
async function makeProofDoc(index = 0, size = 4) {
  const records = Array.from({ length: size }, (_, i) => ({
    facts: { v: 1, recordId: `r${i}`, status: "Closed/Resolved", responseTimeDays: i },
    salt: `${i}`.repeat(64),
  }));
  for (const r of records) r.leaf = await browser.buildLeaf(r.facts, r.salt);

  const leaves = records.map((r) => r.leaf).sort();
  const levels = [leaves];
  while (levels[levels.length - 1].length > 1) {
    const prev = levels[levels.length - 1];
    const next = [];
    for (let i = 0; i < prev.length; i += 2) {
      next.push(await browser.hashPair(prev[i], i + 1 < prev.length ? prev[i + 1] : prev[i]));
    }
    levels.push(next);
  }
  const root = levels[levels.length - 1][0];

  const target = records[index];
  const proof = [];
  let i = leaves.indexOf(target.leaf);
  for (let level = 0; level < levels.length - 1; level++) {
    const nodes = levels[level];
    const isRight = i % 2 === 1;
    const sib = isRight ? i - 1 : i + 1;
    proof.push({
      hash: sib < nodes.length ? nodes[sib] : nodes[i],
      position: isRight ? "left" : "right",
    });
    i = Math.floor(i / 2);
  }

  return {
    anchored: true,
    recordId: target.facts.recordId,
    facts: target.facts,
    salt: target.salt,
    leafHash: target.leaf,
    proof,
    merkleRoot: root,
    leafCount: size,
    period: "2026-09-08",
    cluster: "mainnet-beta",
  };
}

function writeProof(name, doc) {
  const path = join(tmp, name);
  writeFileSync(path, JSON.stringify(doc, null, 2));
  return path;
}

test("--help exits 0 and describes the usage", () => {
  const r = run("--help");
  assert.equal(r.status, 0);
  assert.match(r.stdout, /usage:/);
  assert.match(r.stdout, /--proof <file>/);
});

test("no arguments is a usage error, not a crash", () => {
  const r = run();
  assert.equal(r.status, 2);
  assert.match(r.stderr, /give a record id/);
});

test("an unknown option is rejected by name", () => {
  const r = run("--nope");
  assert.equal(r.status, 2);
  assert.match(r.stderr, /unknown option --nope/);
});

test("an option missing its value says which option", () => {
  // The failure this prevents: --host with nothing after it becoming a fetch
  // of "undefined" and a confusing 404 three steps later.
  const r = run("some-id", "--host");
  assert.equal(r.status, 2);
  assert.match(r.stderr, /--host requires a value/);
});

test("a valid proof verifies, offline, and exits 0", async () => {
  const path = writeProof("good.json", await makeProofDoc(0));
  const r = run("--proof", path, "--no-chain");
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /VERIFIED/);
  // The honesty requirement: with the chain check skipped, the output must not
  // imply anything was checked against the ledger.
  assert.match(r.stdout, /Skipping the on chain check/);
});

test("every leaf in a batch verifies", async () => {
  for (let i = 0; i < 4; i++) {
    const path = writeProof(`good-${i}.json`, await makeProofDoc(i));
    const r = run("--proof", path, "--no-chain");
    assert.equal(r.status, 0, `leaf ${i}: ${r.stdout}${r.stderr}`);
  }
});

test("--json emits a parseable result", async () => {
  const path = writeProof("json.json", await makeProofDoc(1));
  const r = run("--proof", path, "--no-chain", "--json");
  assert.equal(r.status, 0);
  const parsed = JSON.parse(r.stdout);
  assert.equal(parsed.verified, true);
  assert.ok(parsed.checks.length >= 2);
  assert.ok(parsed.checks.every((c) => c.ok));
});

test("a record altered after anchoring fails, and exits 1", async () => {
  const doc = await makeProofDoc(0);
  doc.facts.status = "Ghosted";
  const path = writeProof("tampered-facts.json", doc);

  const r = run("--proof", path, "--no-chain");
  assert.equal(r.status, 1);
  assert.match(r.stdout, /VERIFICATION FAILED/);
  // Which half failed is the useful part, so check it is reported.
  assert.match(r.stdout, /FAIL.*hashes to its published leaf/);
});

test("a fabricated proof path fails at the root, not the leaf", async () => {
  const doc = await makeProofDoc(0);
  doc.proof[0].hash = "0".repeat(64);
  const path = writeProof("tampered-proof.json", doc);

  const r = run("--proof", path, "--no-chain", "--json");
  assert.equal(r.status, 1);
  const parsed = JSON.parse(r.stdout);
  assert.equal(parsed.verified, false);
  assert.equal(parsed.checks[0].ok, true, "the leaf itself is untouched");
  assert.equal(parsed.checks[1].ok, false, "the walk to the root should fail");
});

test("a malformed proof step is reported, not thrown as a stack trace", async () => {
  const doc = await makeProofDoc(0);
  doc.proof[0].position = "sideways";
  const path = writeProof("bad-position.json", doc);

  const r = run("--proof", path, "--no-chain");
  assert.equal(r.status, 1);
  assert.match(r.stdout, /unknown position/);
  assert.doesNotMatch(r.stderr, /at .*verify-anchor\.mjs/);
});

test("a record awaiting its first anchor is not a failure", () => {
  // Exit 0, because "not anchored yet" is a correct answer to the question
  // rather than a failed verification.
  const path = writeProof("pending.json", { anchored: false, reason: "not_yet_anchored" });
  const r = run("--proof", path);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /not anchored yet/);
  assert.match(r.stdout, /next daily run/, "says when to expect it, rather than just no");
});

test("a record whose batch has not confirmed says so specifically", () => {
  const path = writeProof("batch.json", { anchored: false, reason: "batch_pending" });
  const r = run("--proof", path);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /leaf is frozen/);
  assert.match(r.stdout, /not been\s+confirmed on chain/);
});

test("an id that names nothing is a failure, not a wait", () => {
  // The distinction this whole change exists for. Reporting a typo'd id as
  // "not anchored yet" tells someone to wait for something that will never
  // happen, and it is the first thing a reviewer will hit if they mistype.
  const path = writeProof("unknown.json", { anchored: false, reason: "unknown_record" });
  const r = run("--proof", path);
  assert.equal(r.status, 1);
  assert.match(r.stdout, /No record has that id/);
});

test("a publisher with anchoring switched off says that, rather than failing", () => {
  const path = writeProof("off.json", { anchored: false, reason: "not_configured" });
  const r = run("--proof", path);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /has not configured anchoring/);
});

test("an unrecognised reason still produces a sensible line", () => {
  // A publisher may add a reason this verifier has never heard of. Falling
  // back to the raw value beats printing nothing.
  const path = writeProof("odd.json", { anchored: false, reason: "some_future_reason" });
  const r = run("--proof", path);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /some_future_reason/);
});

test("a missing proof file is a usage error with a readable message", () => {
  const r = run("--proof", join(tmp, "does-not-exist.json"));
  assert.equal(r.status, 2);
  assert.match(r.stderr, /could not read proof/);
  assert.doesNotMatch(r.stderr, /at Object\./);
});

test("a proof with no transaction signature fails the chain check", async () => {
  // Without --no-chain the tool must not silently pass a proof it could not
  // check against the ledger.
  const doc = await makeProofDoc(0);
  const path = writeProof("no-sig.json", doc);
  const r = run("--proof", path, "--json");
  assert.equal(r.status, 1);
  const parsed = JSON.parse(r.stdout);
  assert.ok(parsed.checks.some((c) => !c.ok && /no transaction signature/.test(c.label)));
});

test("an unknown cluster asks for --rpc rather than guessing", async () => {
  const doc = await makeProofDoc(0);
  doc.txSignature = "5".repeat(88);
  doc.cluster = "some-private-validator";
  const path = writeProof("odd-cluster.json", doc);

  const r = run("--proof", path, "--json");
  assert.equal(r.status, 1);
  const parsed = JSON.parse(r.stdout);
  assert.ok(parsed.checks.some((c) => !c.ok && /pass --rpc/.test(c.label)));
});
