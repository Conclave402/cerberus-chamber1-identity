/**
 * Chamber 1 (identity) of the Cerberus airlock, as fixed by the Kognai Genesis kit version 1
 * (pact-chambers, sha256 of the kit ff1aa785f196564aca5731a935915445a0d9c77f1451a09eb1bab4cab5831ebc).
 *
 * The types below are the kit's contract for chamber 1, kept byte compatible with
 * https://www.kognai.ai/docs/kits/pact-chambers/src/types.ts so that this module can be dropped
 * in where the reference chamber is, with no change to any caller.
 */

/** A chamber's answer. ok false always comes with a non empty reason. */
export interface Verdict {
  ok: boolean;
  reason: string;
}

/** The identity challenge the listing owner signs. */
export interface Challenge {
  did: string;
  listingId: string;
  /** at least 16 random bytes in hex, never reused */
  nonce: string;
  /** ISO 8601 UTC (toISOString) */
  issuedAt: string;
  /** 1 to 15 minutes after issuedAt */
  expiresAt: string;
  /** challengeMessage(this): the exact text the listing owner signs */
  message: string;
}

/** The three functions of chamber 1, the contract of this module. */
export interface IdentityChamber {
  createChallenge(input: { did: string; listingId: string; now: number }): Challenge;
  /**
   * Six lines joined by "\n", no trailing newline:
   * LAX identity challenge / did: <did> / listing: <listingId> / nonce: <nonce> / issued: <issuedAt> / expires: <expiresAt>
   */
  challengeMessage(challenge: Challenge): string;
  /** EIP-191 signature by ownerAddress over challenge.message; refuses expired, tampered, replayed (a nonce verifies once). */
  verifyChallenge(input: {
    challenge: Challenge;
    signature: string;
    ownerAddress: string;
    now: number;
  }): Verdict | Promise<Verdict>;
}
