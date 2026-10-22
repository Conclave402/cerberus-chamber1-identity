/**
 * Tests of chamber 1. Each test is named after the acceptance item it proves, as the house rules ask.
 *
 * The keys used here are the public test keys of a local development chain. They are public, they hold
 * nothing and they are never funded. No secret and no private key of a real listing is in this file.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { privateKeyToAccount } from 'viem/accounts';
import { CHALLENGE_MAX_TTL_MS, CHALLENGE_MIN_TTL_MS, CHALLENGE_TTL_MS, challengeMessage, createChallenge, resetNonces, verifyChallenge } from '../src/index.ts';
import { claimNonce, isNonceUsed, releaseNonce } from '../src/nonceStore.ts';
import type { Challenge } from '../src/types.ts';

const NOW = Date.parse('2026-10-27T12:00:00.000Z');
const DID = 'did:web:agent-one.example';
const OWNER = privateKeyToAccount('0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d');
const OTHER = privateKeyToAccount('0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a');

const sign = (c: Challenge, who = OWNER) => who.signMessage({ message: challengeMessage(c) });
const verify = (challenge: unknown, signature: unknown, ownerAddress: unknown, now: unknown = NOW + 1000) =>
  verifyChallenge({ challenge, signature, ownerAddress, now } as never);

test('A1 the challenge carries its exact six line message, a fresh nonce and a ten minute lifetime', () => {
  const a = createChallenge({ did: DID, listingId: 'L1', now: NOW });
  const b = createChallenge({ did: DID, listingId: 'L1', now: NOW });
  assert.equal(
    a.message,
    `LAX identity challenge\ndid: ${DID}\nlisting: L1\nnonce: ${a.nonce}\nissued: 2026-10-27T12:00:00.000Z\nexpires: 2026-10-27T12:10:00.000Z`,
  );
  assert.equal(challengeMessage(a), a.message, 'the helper and the field agree');
  assert.match(a.nonce, /^[0-9a-f]{32}$/);
  assert.notEqual(a.nonce, b.nonce, 'every nonce is fresh');
  assert.equal(Date.parse(a.expiresAt) - Date.parse(a.issuedAt), CHALLENGE_TTL_MS);
  assert.ok(CHALLENGE_MIN_TTL_MS <= CHALLENGE_TTL_MS && CHALLENGE_TTL_MS <= CHALLENGE_MAX_TTL_MS);
});

test('A2 a malformed DID, an empty listing id and a bad clock are refused at issue time', () => {
  assert.throws(() => createChallenge({ did: 'nope', listingId: 'L1', now: NOW }), /did must be a DID/);
  assert.throws(() => createChallenge({ did: DID, listingId: '', now: NOW }), /listingId must be a non empty id/);
  assert.throws(() => createChallenge({ did: DID, listingId: 'a b', now: NOW }), /listingId must be a non empty id/);
  assert.throws(() => createChallenge({ did: DID, listingId: 'L1', now: Number.NaN }), /now must be milliseconds/);
  assert.throws(() => createChallenge(undefined as never), /did must be a DID/);
  assert.throws(() => createChallenge({ did: 42, listingId: 'L1', now: NOW }), /did must be a DID/);
});

test('A3 the listing owner signature is accepted, once, with a reason', async () => {
  resetNonces();
  const c = createChallenge({ did: DID, listingId: 'L2', now: NOW });
  const v = await verify(c, await sign(c), OWNER.address);
  assert.equal(v.ok, true, v.reason);
  assert.match(v.reason, /signed by the listing owner/);
});

test('A4 another signer is refused', async () => {
  resetNonces();
  const c = createChallenge({ did: DID, listingId: 'L3', now: NOW });
  const other = await verify(c, await sign(c, OTHER), OWNER.address);
  assert.equal(other.ok, false);
  assert.match(other.reason, /not signed by the listing owner/);
  const wrongOwner = await verify(c, await sign(c), OTHER.address);
  assert.equal(wrongOwner.ok, false, 'a signature by another key against another address');
  const garbage = await verify(c, `0x${'00'.repeat(65)}`, OWNER.address);
  assert.equal(garbage.ok, false, 'a well formed signature that recovers nothing');
});

test('A5 an expired challenge is refused', async () => {
  resetNonces();
  const c = createChallenge({ did: DID, listingId: 'L4', now: NOW });
  const sig = await sign(c);
  const expired = await verify(c, sig, OWNER.address, NOW + CHALLENGE_TTL_MS);
  assert.equal(expired.ok, false);
  assert.match(expired.reason, /expired/);
  const late = await verify(c, sig, OWNER.address, NOW + CHALLENGE_TTL_MS + 1);
  assert.equal(late.ok, false);
});

test('A6 a nonce used twice is refused as a replay, and the nonce is spent exactly once', async () => {
  resetNonces();
  const c = createChallenge({ did: DID, listingId: 'L5', now: NOW });
  const sig = await sign(c);
  const first = await verify(c, sig, OWNER.address);
  assert.equal(first.ok, true, first.reason);
  const second = await verify(c, sig, OWNER.address);
  assert.equal(second.ok, false);
  assert.match(second.reason, /replay/);
  assert.equal(isNonceUsed(c.nonce), true);
  assert.equal(claimNonce(c.nonce), false, 'a spent nonce cannot be claimed again');
  assert.equal(claimNonce('0'.repeat(32)), true);
  releaseNonce('0'.repeat(32));
  assert.equal(isNonceUsed('0'.repeat(32)), false, 'a released nonce can be claimed again');
  resetNonces();
  assert.equal(isNonceUsed(c.nonce), false, 'the store can be emptied for a fresh run');
  const concurrent = createChallenge({ did: DID, listingId: 'L5b', now: NOW });
  const concurrentSig = await sign(concurrent);
  const pair = await Promise.all([verify(concurrent, concurrentSig, OWNER.address), verify(concurrent, concurrentSig, OWNER.address)]);
  assert.equal(pair.filter((r) => r.ok).length, 1, 'exactly one of two verifications at the same time succeeds');
});

test('A7 a tampered DID, a rebuilt message and a tampered field are refused', async () => {
  resetNonces();
  const c = createChallenge({ did: DID, listingId: 'L6', now: NOW });
  const sig = await sign(c);
  const changedDid = { ...c, did: 'did:web:evil.example' };
  const tampered = await verify(changedDid, sig, OWNER.address);
  assert.equal(tampered.ok, false, 'a changed DID no longer matches the message');
  assert.match(tampered.reason, /tampered/);
  const rebuilt = { ...c, did: 'did:web:evil.example' };
  rebuilt.message = challengeMessage(rebuilt);
  const forged = await verify(rebuilt, sig, OWNER.address);
  assert.equal(forged.ok, false, 'a rebuilt message is not what the owner signed');
  const otherListing = { ...c, listingId: 'other' };
  otherListing.message = challengeMessage(otherListing);
  const moved = await verify(otherListing, sig, OWNER.address);
  assert.equal(moved.ok, false, 'a challenge moved to another listing is refused');
});

test('A8 malformed input is refused, with a reason', async () => {
  resetNonces();
  const c = createChallenge({ did: DID, listingId: 'L7', now: NOW });
  const sig = await sign(c);
  assert.equal((await verify(null, sig, OWNER.address)).ok, false);
  assert.equal((await verify(undefined, sig, OWNER.address)).ok, false);
  assert.equal((await verifyChallenge(undefined as never)).ok, false);
  assert.equal((await verify(c, '0x12', OWNER.address)).ok, false);
  assert.equal((await verify(c, sig, 'x')).ok, false);
  assert.equal((await verify(c, sig, OWNER.address, 'soon')).ok, false);
  assert.equal((await verify(c, sig, OWNER.address, Number.NaN)).ok, false);
  const shortNonce = { ...c, nonce: 'short' };
  shortNonce.message = challengeMessage(shortNonce);
  assert.equal((await verify(shortNonce, sig, OWNER.address)).ok, false);
  const numberNonce = { ...c, nonce: 12345 };
  numberNonce.message = challengeMessage(numberNonce);
  assert.equal((await verify(numberNonce, sig, OWNER.address)).ok, false);
  const noDid = { ...c, did: 7 };
  noDid.message = challengeMessage(noDid);
  assert.equal((await verify(noDid, sig, OWNER.address)).ok, false);
  const noListing = { ...c, listingId: null };
  noListing.message = challengeMessage(noListing);
  assert.equal((await verify(noListing, sig, OWNER.address)).ok, false);
  const notIso = { ...c, issuedAt: '2026-10-27T12:00:00Z' };
  notIso.message = challengeMessage(notIso);
  assert.equal((await verify(notIso, sig, OWNER.address)).ok, false);
  const badDate = { ...c, expiresAt: 'not a date' };
  badDate.message = challengeMessage(badDate);
  assert.equal((await verify(badDate, sig, OWNER.address)).ok, false);
  const tooLong = { ...c, expiresAt: new Date(NOW + 60 * 60_000).toISOString() };
  tooLong.message = challengeMessage(tooLong);
  assert.equal((await verify(tooLong, await sign(tooLong), OWNER.address)).ok, false, 'a lifetime over 15 minutes is refused');
  const tooShort = { ...c, expiresAt: new Date(NOW + 1000).toISOString() };
  tooShort.message = challengeMessage(tooShort);
  assert.equal((await verify(tooShort, await sign(tooShort), OWNER.address)).ok, false, 'a lifetime under 1 minute is refused');
  const throwing = { ...c };
  Object.defineProperty(throwing, 'message', { get() { throw new Error('boom'); } });
  const caught = await verify(throwing, sig, OWNER.address);
  assert.equal(caught.ok, false);
  assert.match(caught.reason, /malformed/);
});
