// Hand written, because src/browser.mjs deliberately has no build step: what
// you read there is what runs in the browser. Keep these in step by hand.

export interface ProofStep {
  hash: string;
  /** The side the SIBLING sits on, not the side of the node being proved. */
  position: "left" | "right";
}

export interface Memo {
  prefix: string;
  version: number;
  period: string;
  root: string;
}

export interface VerificationCheck {
  label: string;
  ok: boolean;
  detail?: string;
}

export interface ProofDocument {
  /** The committed facts. `snapshot` is accepted as a legacy alias. */
  facts?: Record<string, unknown>;
  snapshot?: Record<string, unknown>;
  salt?: string;
  leafHash?: string;
  proof?: ProofStep[];
  merkleRoot?: string;
  /**
   * The memo string read from the transaction by the caller. Supply it to get
   * the third check, comparing the computed root against what was published.
   * Without it, verification shows internal consistency only.
   */
  onChainMemo?: string;
  memoPrefix?: string;
  [key: string]: unknown;
}

export function canonicalJson(value: unknown): string;
export function buildLeaf(facts: Record<string, unknown>, salt: string): Promise<string>;
export function hashPair(left: string, right: string): Promise<string>;
export function walkProof(leaf: string, proof: ProofStep[]): Promise<string>;
export function parseMemo(memo: string, expectedPrefix?: string): Memo | null;
export function verifyAnchor(proof: ProofDocument): Promise<VerificationCheck[]>;
