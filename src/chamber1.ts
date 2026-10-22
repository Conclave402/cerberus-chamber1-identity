/**
 * Chamber 1 of the Cerberus airlock: the identity challenge.
 *
 * A listed agent proves it controls its LAX listing. The airlock hands it a challenge that names
 * the agent DID, the listing id, a fresh nonce and an expiry; the listing owner signs the exact
 * challenge text with EIP-191 (personal_sign); the chamber verifies the signature against the
 * owner address and refuses when anything does not line up:
 *
 *   another signer, an expired challenge, tampered fields, a nonce used twice (replay), malformed input.
 *
 * No network, no clock of its own: the caller passes `now` in milliseconds since the epoch, so
 * every result is reproducible. The only dependency is viem, for the EIP-191 signature check.
 *
 * The formats are the ones fixed by the Kognai Genesis kit version 1 (pact-chambers), so this module
 * can be dropped in where the reference chamber is, with no change to any caller.
 */
import { randomBytes } from 'node:crypto';
import { verifyMessage } from 'viem';
import { claimNonce, releaseNonce } from './nonceStore.ts';
import type { Challenge, IdentityChamber, Verdict } from './types.ts';

/** The lifetime of a challenge: 10 minutes, inside the 1 to 15 minutes the contract allows. */
export const CHALLENGE_TTL_MS = 10 * 60_000;
/** The shortest lifetime the contract allows. */
export const CHALLENGE_MIN_TTL_MS = 60_000;
/** The longest lifetime the contract allows. */
export const CHALLENGE_MAX_TTL_MS = 15 * 60_000;
/** The nonce is 16 random bytes in hex, as the contract asks. */
export const NONCE_BYTES = 16;

/** A DID, as the contract writes it: did:<method>:<value> with no space. */
const DID_RE = /^did:[a-z0-9]+:\S+$/;
/** A nonce: hex, at least 16 bytes. */
const NONCE_RE = /^[0-9a-f]{32,}$/;
/** An EIP-191 compact signature: 0x plus 130 hex characters (r, s and v). */
const SIGNATURE_RE = /^0x[0-9a-fA-F]{130}$/;
/** An Ethereum address: 0x plus 40 hex characters. */
const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;

/** True for an ISO 8601 UTC timestamp in the exact toISOString form. */
const isIso = (s: unknown): s is string =>
  typeof s === 'string' && Number.isFinite(Date.parse(s)) && new Date(Date.parse(s)).toISOString() === s;

const refuse = (reason: string): Verdict => ({ ok: false, reason });

/**
 * The exact text the listing owner signs: six lines joined by "\n", no trailing newline.
 * The order and the wording are fixed by the contract and must not change.
 */
export function challengeMessage(c: Challenge): string {
  return [
    'LAX identity challenge',
    `did: ${c.did}`,
    `listing: ${c.listingId}`,
    `nonce: ${c.nonce}`,
    `issued: ${c.issuedAt}`,
    `expires: ${c.expiresAt}`,
  ].join('\n');
}

/**
 * Issues a challenge for one agent and one listing.
 *
 * The nonce is 16 fresh random bytes, never reused; the challenge lives 10 minutes.
 * Malformed input throws: a challenge that cannot be built is a caller error, not a refusal.
 */
export function createChallenge(input: { did: string; listingId: string; now: number }): Challenge {
  const { did, listingId, now } = input || ({} as { did: string; listingId: string; now: number });
  if (typeof did !== 'string' || !DID_RE.test(did)) throw new Error('did must be a DID');
  if (typeof listingId !== 'string' || !listingId.trim() || /\s/.test(listingId)) {
    throw new Error('listingId must be a non empty id');
  }
  if (typeof now !== 'number' || !Number.isFinite(now)) {
    throw new Error('now must be milliseconds since the epoch');
  }
  const challenge: Challenge = {
    did,
    listingId,
    nonce: randomBytes(NONCE_BYTES).toString('hex'),
    issuedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + CHALLENGE_TTL_MS).toISOString(),
    message: '',
  };
  challenge.message = challengeMessage(challenge);
  return challenge;
}

/**
 * Verifies the listing owner's signature over the challenge text.
 *
 * Every refusal carries a reason that names what did not line up. A nonce verifies once: a second
 * attempt with the same challenge is refused as a replay.
 */
export async function verifyChallenge(input: {
  challenge: Challenge;
  signature: string;
  ownerAddress: string;
  now: number;
}): Promise<Verdict> {
  try {
    const { challenge: c, signature, ownerAddress, now } = input || ({} as typeof input);
    if (!c || typeof c !== 'object') return refuse('no challenge');
    if (
      typeof c.did !== 'string' ||
      typeof c.listingId !== 'string' ||
      !NONCE_RE.test(String(c.nonce)) ||
      !isIso(c.issuedAt) ||
      !isIso(c.expiresAt)
    ) {
      return refuse('the challenge is malformed');
    }
    if (c.message !== challengeMessage(c)) {
      return refuse('the challenge text does not match its fields (tampered)');
    }
    const ttl = Date.parse(c.expiresAt) - Date.parse(c.issuedAt);
    if (ttl < CHALLENGE_MIN_TTL_MS || ttl > CHALLENGE_MAX_TTL_MS) {
      return refuse('the challenge lifetime is not between 1 and 15 minutes');
    }
    if (typeof now !== 'number' || !Number.isFinite(now)) {
      return refuse('now must be milliseconds since the epoch');
    }
    if (now >= Date.parse(c.expiresAt)) return refuse('the challenge expired');
    if (!claimNonce(c.nonce)) return refuse('the challenge was already used (replay)');
    if (typeof signature !== 'string' || !SIGNATURE_RE.test(signature)) {
      releaseNonce(c.nonce);
      return refuse('the signature is malformed');
    }
    if (typeof ownerAddress !== 'string' || !ADDRESS_RE.test(ownerAddress)) {
      releaseNonce(c.nonce);
      return refuse('the owner address is malformed');
    }
    let signed = false;
    try {
      signed = await verifyMessage({
        address: ownerAddress as `0x${string}`,
        message: c.message,
        signature: signature as `0x${string}`,
      });
    } catch {
      signed = false;
    }
    if (!signed) {
      releaseNonce(c.nonce);
      return refuse('the challenge is not signed by the listing owner');
    }
    return { ok: true, reason: 'signed by the listing owner' };
  } catch {
    return refuse('the input is malformed');
  }
}

/** The chamber, as one object, for callers that take the whole set. */
export const identityChamber: IdentityChamber = { createChallenge, challengeMessage, verifyChallenge };
