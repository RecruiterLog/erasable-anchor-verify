// Do the two implementations agree on data they have never seen?
//
// The vectors cover known cases. This covers the ones nobody thought to write
// down: unicode, embedded quotes, nulls, zero, negative numbers, deep nesting.
// Those are where two hand written canonicalisers actually diverge, because
// each author had a slightly different idea of what JSON.stringify does.

import { test } from "node:test";
import assert from "node:assert/strict";

import * as browser from "../src/browser.mjs";
import * as cli from "../bin/verify-anchor.mjs";

// A small deterministic PRNG, so a failure is reproducible from its seed
// rather than vanishing on the next run.
function rng(seed) {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 0x100000000;
  };
}

const ROLES = [
  "Backend Engineer",
  'Odd "quoted" role',
  "Ünicode Rôle",
  "emoji 🙃 role",
  "tab\tand\nnewline",
  "back\\slash",
  "",
  null,
];

function randomFacts(rand) {
  const pick = (a) => a[Math.floor(rand() * a.length)];
  return {
    v: 1,
    recordId: `rec-${Math.floor(rand() * 1e9)}`,
    companyId: pick(["c-1", "some-company", null, "a.b_c~d"]),
    recruiterRef: pick([null, `rp-${Math.floor(rand() * 1e6)}`]),
    role: pick(ROLES),
    status: pick(["Ghosted", "Closed/Resolved"]),
    responseTimeDays: pick([0, -0, 1, 14, 365, 0.5, -3, null]),
    isGhosted: pick([true, false]),
    everBreached: pick([true, false]),
    createdAt: pick([new Date(Math.floor(rand() * 1e12)).toISOString(), null]),
    nested: pick([
      null,
      { z: 1, a: [1, 2, { b: false, a: null }] },
      { "": "empty key" },
    ]),
  };
}

const randomSalt = (rand) =>
  Array.from({ length: 64 }, () => "0123456789abcdef"[Math.floor(rand() * 16)]).join("");

test("canonicalJson agrees across 2000 random records", () => {
  const rand = rng(20260908);
  for (let i = 0; i < 2000; i++) {
    const facts = randomFacts(rand);
    assert.equal(
      browser.canonicalJson(facts),
      cli.canonicalJson(facts),
      `divergence at record ${i}: ${JSON.stringify(facts)}`
    );
  }
});

test("buildLeaf agrees across 2000 random records", async () => {
  const rand = rng(99991);
  for (let i = 0; i < 2000; i++) {
    const facts = randomFacts(rand);
    const salt = randomSalt(rand);
    assert.equal(
      await browser.buildLeaf(facts, salt),
      cli.buildLeaf(facts, salt),
      `divergence at record ${i}`
    );
  }
});

test("hashPair agrees across 500 random pairs", async () => {
  const rand = rng(7);
  for (let i = 0; i < 500; i++) {
    const l = randomSalt(rand);
    const r = randomSalt(rand);
    assert.equal(await browser.hashPair(l, r), cli.hashPair(l, r));
  }
});

test("a tree built by one implementation verifies under the other", async () => {
  const rand = rng(31337);

  for (const n of [1, 2, 3, 5, 8, 13]) {
    // Build with the browser implementation.
    const records = Array.from({ length: n }, () => ({
      facts: randomFacts(rand),
      salt: randomSalt(rand),
    }));
    for (const r of records) r.leaf = await browser.buildLeaf(r.facts, r.salt);

    const leaves = records.map((r) => r.leaf).sort();
    const levels = [leaves];
    while (levels[levels.length - 1].length > 1) {
      const prev = levels[levels.length - 1];
      const next = [];
      for (let i = 0; i < prev.length; i += 2) {
        // The duplicate last rule, per SPEC.md section 4.
        next.push(await browser.hashPair(prev[i], i + 1 < prev.length ? prev[i + 1] : prev[i]));
      }
      levels.push(next);
    }
    const root = levels[levels.length - 1][0];

    // Extract each proof, then verify it with the CLI implementation.
    for (let idx = 0; idx < n; idx++) {
      const proof = [];
      // The leaf's position in the SORTED leaves, not its position in the
      // record list. Sorting is what makes the order a property of the set,
      // and it means these two indexes are unrelated for any n above 1.
      let i = leaves.indexOf(records[idx].leaf);
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

      const leaf = cli.buildLeaf(records[idx].facts, records[idx].salt);
      assert.equal(cli.walkProof(leaf, proof), root, `n=${n} leaf ${idx}`);
    }
  }
});
