/**
 * Replay protection for chamber 1.
 *
 * A nonce verifies once: the store keeps the nonces already spent, so a signature captured from one
 * request cannot be replayed with another.
 *
 * The store hands the nonce out with `claimNonce` and takes it back with `releaseNonce` when the
 * signature turns out not to be the owner's. That order matters: the nonce is claimed before the
 * signature is checked, so two verifications of the same challenge that run at the same time cannot
 * both succeed, and a failed attempt does not burn the nonce, so the owner may try again.
 *
 * The store is in memory and per process, which is what the airlock needs (a challenge lives for
 * minutes and never crosses a process boundary in the kit's flow). A deployment that runs several
 * processes must give every process the same store, for example a shared database, or a challenge
 * may be accepted twice.
 */

const usedNonces = new Set<string>();

/** True when the nonce was already spent. */
export function isNonceUsed(nonce: string): boolean {
  return usedNonces.has(nonce);
}

/**
 * Takes the nonce for this verification. Returns false when it was already taken, so a second
 * attempt with the same challenge is a replay and cannot succeed.
 */
export function claimNonce(nonce: string): boolean {
  if (usedNonces.has(nonce)) return false;
  usedNonces.add(nonce);
  return true;
}

/** Gives the nonce back, for an attempt that did not end in a verification. */
export function releaseNonce(nonce: string): void {
  usedNonces.delete(nonce);
}

/** Test helper: forgets every spent nonce. */
export function resetNonces(): void {
  usedNonces.clear();
}
