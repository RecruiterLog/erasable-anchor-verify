# erasable-anchor-verify

Independent verifiers for [erasable-anchor](https://github.com/RecruiterLog/erasable-anchor)
proofs: a Web Crypto module for the browser, and a zero-dependency CLI.

```
npx erasable-anchor-verify <record-id>
```

## Check a live record yourself, in thirty seconds

No install, no clone, no account, and no cooperation from RecruiterLog beyond
the data they serve:

```bash
curl -sO https://raw.githubusercontent.com/RecruiterLog/erasable-anchor-verify/main/bin/verify-anchor.mjs
node verify-anchor.mjs f9ab4eff-01d5-49ef-a682-9b457b9e6d94
```

One file, about 12 kB, no dependencies beyond Node's built-in `crypto` and
`fetch`. **Read it before you run it.** It is deliberately short enough to read
in full, and a verifier you have not read is just a second opinion from a
stranger.

You should see the record's leaf recomputed from its own content, the proof
walked to a root, and that root read back off Solana mainnet from a public RPC
node rather than from RecruiterLog:

```
memo: rl:v1:2026-09-07:ee0885119c798d763c2930ba6df749aecbb19d25cb69c3c9e9d...
OK    the record's content still hashes to its published leaf
OK    the leaf is genuinely part of the claimed tree
OK    the root we computed is the root published on chain
VERIFIED. This record is unchanged since it was anchored.
```

Exit code 0 for verified, 1 for failed. To pick your own record rather than
ours, take any id from [recruiterlog.com/ledger](https://recruiterlog.com/ledger);
records anchor on the next daily run after they settle, so a recent one may
report that it is not anchored yet, which is a correct answer rather than a
failure.

If you would rather not trust a single RPC provider, pass `--rpc` with an
endpoint of your choosing. The proof is fetched from RecruiterLog because only
they hold it; the root is not.

## Why this is a separate package

A verifier that imported the library it checks would be confirming that
library's arithmetic with that library's own code. It would agree by
construction and prove nothing.

So both verifiers here are written from
[the spec](https://github.com/RecruiterLog/erasable-anchor/blob/main/SPEC.md),
not from the implementation, and neither imports it. They are held in
agreement by a conformance suite that runs both against the fixed vectors
published with the spec, plus a fuzz check across 2,000 randomly generated
records covering the cases that actually cause two hand written
canonicalisers to diverge: unicode, embedded quotes, tabs, empty keys,
negative zero.

One of the tests asserts that neither verifier imports anything but Node
builtins. That is there to stop a future tidy up quietly removing the only
reason this package exists.

## The CLI

```
verify-anchor <record-id> [--host https://recruiterlog.com]
verify-anchor --proof ./proof.json --no-chain     verify a saved proof, offline
verify-anchor <record-id> --json                  machine readable output
```

Four things happen, in order:

1. Fetch the record's proof. **Data only.** Every hash is recomputed locally.
2. Recompute the leaf from the record's own content and salt.
3. Walk the sibling path to the root.
4. Read the published root straight off a public Solana RPC node, and compare.

Step 4 is the one that matters. Steps 2 and 3 show a proof is internally
consistent, which a fabricated proof also is. Reading the root from the chain
is what removes the need to trust whoever served it.

Exit codes are `0` verified, `1` failed, `2` usage error, so it drops into CI
or a cron check without parsing output. `--json` gives a per check result if
you want the detail.

`bin/verify-anchor.mjs` is a single file with no dependencies beyond Node's
built-in `crypto` and `fetch`. Copy it anywhere and it runs. That portability
is deliberate: a verifier nobody can run without installing your toolchain is
not much of an independent check.

## The browser module

```js
import { verifyAnchor } from "erasable-anchor-verify";

const checks = await verifyAnchor(proofDocument);
// [ { label: "The record's content still hashes to its published fingerprint",
//     ok: true, detail: "de7467..." }, ... ]
```

`verifyAnchor` returns one check per step rather than a boolean, because when
verification fails, *which* half failed is the only useful information. A leaf
mismatch means the record changed after it was anchored. A root mismatch means
the proof does not belong to the tree it claims. Collapsing both into `false`
throws that away.

Pass `onChainMemo`, read from the transaction yourself, to add the comparison
against what was actually published. Without it the checks show internal
consistency and nothing about the ledger, and the returned labels say so.

No build step and no dependencies: `src/browser.mjs` is plain ESM, so what you
read is what runs. Web Crypto needs a secure context, which means https or
localhost.

`examples/verify.html` is a working page. It needs to be served rather than
opened from disk, because browsers block module imports over `file://`:

```
npx serve .        then open /examples/verify.html
```

## What a passing result establishes

**Does:** this exact content was included in a tree whose root was published
at the stated time by whoever controls the publishing key, and has not been
altered since.

**Does not:** that the batch was complete. Nothing on a ledger can show that
records were never withheld before publication.

Both halves are printed on every run. A tool that oversells what it verified
is worse than no tool, because people stop reading the failures.

## Tests

```
npm test
```

41 tests, no dependencies. The CLI ones spawn the actual binary and assert on
exit codes and output rather than importing its functions, because exit codes
are the entire interface for anyone wiring this into CI and are easy to get
wrong in a way no unit test notices.

## Licence

Apache 2.0. See `LICENSE` and `NOTICE`.
