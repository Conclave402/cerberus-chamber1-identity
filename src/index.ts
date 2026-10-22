/**
 * cerberus-chamber1-identity: the identity chamber of the Cerberus airlock.
 *
 * A thin entry point over the module. The rules of the house: one router for models, no secrets in
 * code or logs, text people see in Latin digits and plain words, small single concern files.
 */
export { CHALLENGE_MAX_TTL_MS, CHALLENGE_MIN_TTL_MS, CHALLENGE_TTL_MS, NONCE_BYTES, challengeMessage, createChallenge, identityChamber, verifyChallenge } from './chamber1.ts';
export { claimNonce, isNonceUsed, releaseNonce, resetNonces } from './nonceStore.ts';
export type { Challenge, IdentityChamber, Verdict } from './types.ts';
