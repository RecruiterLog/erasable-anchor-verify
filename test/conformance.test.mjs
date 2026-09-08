// Conformance: both verifiers against the fixed vectors published with the
// spec.
//
// This is the test that makes "independent implementation" mean something. The
// vectors come from erasable-anchor and are copied here verbatim, so passing
// them shows agreement with a implementation this code never imports. If the
// two ever diverge, every proof would fail for outsiders while passing inside
// the system that produced it, which is the worst possible failure mode: it
// looks like tampering.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import * as browser from "../src/browser.mjs";
import * as cli from "../bin/verify-anchor.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(join(here, "vectors.json"), "utf8"));

// Both implementations, run through the same assertions. Named so a failure
// says which one broke.
const impls = [
  ["browser (Web Crypto)", browser],
  ["cli (node:crypto)", cli],
];

for (const [name, impl] of impls) {
  test(`${name}: canonicalJson matches every vector`, () => {
    for (const c of vectors.canonicalJson) {
      assert.equal(impl.canonicalJson(c.value), c.canonical, c.note);
    }
  });

  test(`${name}: hashPair matches every vector`, async () => {
    for (const c of vectors.hashPair) {
      assert.equal(await impl.hashPair(c.left, c.right), c.hash);
    }
  });

  test(`${name}: buildLeaf matches every vector`, async () => {
    for (const c of vectors.buildLeaf) {
      assert.equal(await impl.buildLeaf(c.facts, c.salt), c.leaf, c.note);
    }
  });

  test(`${name}: every recorded proof walks to its recorded root`, async () => {
    for (const t of vectors.trees) {
      for (let i = 0; i < t.leaves.length; i++) {
        assert.equal(
          await impl.walkProof(t.leaves[i], t.proofs[i]),
          t.root,
          `size ${t.size} leaf ${i}`
        );
      }
    }
  });

  test(`${name}: recorded memos parse`, () => {
    for (const memo of vectors.memos) {
      const parsed = impl.parseMemo(memo);
      assert.ok(parsed, memo);
      assert.equal(`${parsed.prefix}:v${parsed.version}:${parsed.period}:${parsed.root}`, memo);
    }
  });

  test(`${name}: a tampered leaf does not reach the root`, async () => {
    const t = vectors.trees.find((x) => x.size === 8);
    const tampered = "0".repeat(64);
    assert.notEqual(await impl.walkProof(tampered, t.proofs[0]), t.root);
  });

  test(`${name}: a flipped position does not reach the root`, async () => {
    const t = vectors.trees.find((x) => x.size === 8);
    const flipped = t.proofs[0].map((s) => ({
      ...s,
      position: s.position === "left" ? "right" : "left",
    }));
    assert.notEqual(await impl.walkProof(t.leaves[0], flipped), t.root);
  });

  test(`${name}: rejects facts carrying their own salt key`, async () => {
    await assert.rejects(
      async () => impl.buildLeaf({ a: 1, salt: "mine" }, "0".repeat(64)),
      /must not contain/
    );
  });

  test(`${name}: rejects an empty salt`, async () => {
    // A silently accepted empty salt would produce a real looking hash with no
    // erasure property at all.
    await assert.rejects(async () => impl.buildLeaf({ a: 1 }, ""), /non-empty string/);
  });

  test(`${name}: rejects an unknown proof step position`, async () => {
    await assert.rejects(
      async () => impl.walkProof("0".repeat(64), [{ hash: "1".repeat(64), position: "up" }]),
      /unknown position/
    );
  });

  test(`${name}: an expected prefix excludes another system's memo`, () => {
    const root = "f".repeat(64);
    assert.ok(impl.parseMemo(`rl:v1:2026-09-08:${root}`, "rl"));
    assert.equal(impl.parseMemo(`other:v1:2026-09-08:${root}`, "rl"), null);
    assert.equal(impl.parseMemo(`rl:v1:2026-09-08:${root}`, "r."), null);
  });
}

test("the two implementations are genuinely separate modules", () => {
  // Guards against the refactor that would quietly destroy the point of this
  // package: making one of these import the other, or import erasable-anchor.
  const sources = [
    readFileSync(join(here, "..", "src", "browser.mjs"), "utf8"),
    readFileSync(join(here, "..", "bin", "verify-anchor.mjs"), "utf8"),
  ];
  for (const src of sources) {
    const imports = [...src.matchAll(/^\s*import[^;]*from\s+"([^"]+)"/gm)].map((m) => m[1]);
    for (const spec of imports) {
      assert.ok(
        spec.startsWith("node:"),
        `verifiers may only import node builtins, found ${JSON.stringify(spec)}`
      );
    }
  }
});
