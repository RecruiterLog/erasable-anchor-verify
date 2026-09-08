// Browser verification of an erasable-anchor proof, using Web Crypto.
//
// This is deliberately a SECOND implementation of the hashing rules described
// in erasable-anchor's SPEC.md. It does not import that package, and it must
// not be changed to. The entire value of a proof is that the reader's own
// machine recomputes it: a panel that rendered a boolean the server sent would
// prove nothing, and a verifier that imported the library would be checking
// the library's arithmetic with the library's own code.
//
// The two implementations are held in agreement by the conformance suite in
// test/, which runs both against the fixed vectors published with the spec.
//
// No build step and no dependencies. What you read here is what runs.

/**
 * Canonical serialisation: keys sorted at every depth, no whitespace,
 * undefined collapsed to null. See SPEC.md section 1.
 *
 * @param {unknown} value
 * @returns {string}
 */
export function canonicalJson(value) {
  if (value === null || value === undefined) return "null";

  const t = typeof value;
  if (t === "boolean" || t === "string") return JSON.stringify(value);
  if (t === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("canonicalJson: NaN and Infinity are not representable");
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (t === "object") {
    const keys = Object.keys(value).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(",")}}`;
  }
  throw new Error(`canonicalJson: unsupported type ${t}`);
}

const toHex = (buf) =>
  Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

const fromHex = (hex) => {
  if (typeof hex !== "string" || !/^[0-9a-f]*$/.test(hex) || hex.length % 2 !== 0) {
    throw new Error("fromHex: expected an even length lowercase hex string");
  }
  return new Uint8Array((hex.match(/.{2}/g) || []).map((b) => parseInt(b, 16)));
};

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

function subtle() {
  const c = globalThis.crypto;
  if (!c || !c.subtle) {
    // Web Crypto is unavailable on an insecure origin, which is the one
    // failure here that looks like a bug in the proof rather than in the page.
    throw new Error(
      "Web Crypto is unavailable. This requires a secure context (https, or localhost)."
    );
  }
  return c.subtle;
}

async function sha256(bytes) {
  return toHex(await subtle().digest("SHA-256", bytes));
}

/**
 * Hash a record's facts and salt into a leaf. SPEC.md section 2.
 *
 * @param {Record<string, unknown>} facts
 * @param {string} salt
 * @returns {Promise<string>}
 */
export async function buildLeaf(facts, salt) {
  if (facts === null || typeof facts !== "object" || Array.isArray(facts)) {
    throw new Error("buildLeaf: facts must be a plain object");
  }
  if (Object.prototype.hasOwnProperty.call(facts, "salt")) {
    throw new Error('buildLeaf: facts must not contain a "salt" key');
  }
  if (typeof salt !== "string" || salt.length === 0) {
    throw new Error("buildLeaf: salt must be a non-empty string");
  }
  const payload = new TextEncoder().encode(canonicalJson({ ...facts, salt }));
  return sha256(concat(new Uint8Array([0x00]), payload));
}

/**
 * Hash two child hashes into their parent. SPEC.md section 3.
 *
 * @param {string} left
 * @param {string} right
 * @returns {Promise<string>}
 */
export async function hashPair(left, right) {
  return sha256(concat(new Uint8Array([0x01]), fromHex(left), fromHex(right)));
}

/**
 * Walk a sibling path from a leaf to a root. SPEC.md section 5.
 *
 * @param {string} leaf
 * @param {{hash: string, position: "left" | "right"}[]} proof
 * @returns {Promise<string>}
 */
export async function walkProof(leaf, proof) {
  let acc = leaf;
  for (const step of proof) {
    if (step.position !== "left" && step.position !== "right") {
      throw new Error(`walkProof: unknown position ${JSON.stringify(step.position)}`);
    }
    acc = step.position === "left" ? await hashPair(step.hash, acc) : await hashPair(acc, step.hash);
  }
  return acc;
}

/** Parse an on chain memo. SPEC.md section 7. */
export function parseMemo(memo, expectedPrefix) {
  const prefixPart = expectedPrefix
    ? expectedPrefix.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
    : "[a-z0-9]{1,16}";
  const m = String(memo).match(
    new RegExp(`^(${prefixPart}):v(\\d+):([0-9-]+):([0-9a-f]{64})$`)
  );
  if (!m) return null;
  return { prefix: m[1], version: Number(m[2]), period: m[3], root: m[4] };
}

/**
 * Verify a proof, returning one check per step.
 *
 * Deliberately a list rather than a boolean. When verification fails, which
 * half failed is the only useful information: a leaf mismatch means the record
 * changed after it was anchored, and a root mismatch means the proof does not
 * belong to the tree it claims. Collapsing both into false throws that away.
 *
 * @param {object} proof A proof document: facts (or snapshot), salt, leafHash,
 *   proof, merkleRoot. Optionally onChainMemo and memoPrefix, which add the
 *   third check.
 * @returns {Promise<{label: string, ok: boolean, detail?: string}[]>}
 */
export async function verifyAnchor(proof) {
  const checks = [];
  const facts = proof.facts ?? proof.snapshot;

  let leaf;
  try {
    leaf = await buildLeaf(facts, proof.salt);
  } catch (err) {
    return [
      {
        label: "Recompute the record's fingerprint from its own content",
        ok: false,
        detail: err.message,
      },
    ];
  }

  checks.push({
    label: "The record's content still hashes to its published fingerprint",
    ok: leaf === proof.leafHash,
    detail: leaf,
  });

  const steps = proof.proof || [];
  let root;
  try {
    root = await walkProof(leaf, steps);
  } catch (err) {
    checks.push({ label: "Walk the proof to the root", ok: false, detail: err.message });
    return checks;
  }

  checks.push({
    label: `Walking ${steps.length} sibling hash${steps.length === 1 ? "" : "es"} reaches the published root`,
    ok: root === proof.merkleRoot,
    detail: root,
  });

  // Only present when the caller read the transaction itself. Without it the
  // first two checks show internal consistency and nothing about the ledger,
  // which is worth being honest about rather than implying more.
  if (proof.onChainMemo) {
    const parsed = parseMemo(proof.onChainMemo, proof.memoPrefix);
    checks.push({
      label: "The root we computed is the root published on chain",
      ok: !!parsed && parsed.root === root,
      detail: parsed ? parsed.root : `unparseable memo: ${proof.onChainMemo}`,
    });
  }

  return checks;
}
