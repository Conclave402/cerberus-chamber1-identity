# cerberus-chamber1-identity

Chamber 1 of the Cerberus airlock: the identity challenge.

A listed agent proves it controls its LAX listing. The airlock hands the agent a challenge that
names the agent DID, the listing id, a fresh nonce and an expiry. The listing owner signs the exact
challenge text with EIP-191 (personal_sign). The chamber verifies that signature against the owner
address and refuses when anything does not line up:

- another signer,
- an expired challenge,
- tampered fields,
- a nonce used twice (replay),
- malformed input.

No network. No clock of its own: the caller passes `now` in milliseconds since the epoch, so every
result is reproducible. The only dependency is viem, for the EIP-191 signature check.

## Why this module exists

Seat SEAT1 of the Kognai Genesis sprint builds the real chamber 1. The formats are fixed by the
Kognai chamber interfaces kit version 1 (`pact-chambers`, kit sha256
`ff1aa785f196564aca5731a935915445a0d9c77f1451a09eb1bab4cab5831ebc`), so this module can be dropped in
where the reference chamber is, with no change to any caller:

```bash
CERBERUS_CHAMBERS=/path/to/this/module.mts npm test
```

The kit's own suite passes with this chamber in place, including the cases where another key signed
the challenge, where the challenge expired, where the message was rebuilt, and where the same nonce
was replayed.

## Interface

```ts
import { challengeMessage, createChallenge, verifyChallenge } from 'cerberus-chamber1-identity';

const challenge = createChallenge({ did: 'did:web:agent.example', listingId: 'lax-ext-1', now: Date.now() });
// the owner signs challenge.message with personal_sign
const verdict = await verifyChallenge({ challenge, signature, ownerAddress: '0x...', now: Date.now() });
// { ok: true, reason: 'signed by the listing owner' }
```

`challengeMessage(challenge)` is the exact text that is signed: six lines joined by `"\n"`, with no
trailing newline.

```
LAX identity challenge
did: <did>
listing: <listingId>
nonce: <nonce>
issued: <issuedAt>
expires: <expiresAt>
```

`verifyChallenge` answers `{ ok, reason }`. When `ok` is false the reason is never empty and names
what did not line up.

## Acceptance items and the tests that prove them

| item | what it proves | test |
|---|---|---|
| A1 | the challenge carries its exact six line message, a fresh 16 byte nonce and a ten minute lifetime | `A1 the challenge carries its exact six line message, a fresh nonce and a ten minute lifetime` |
| A2 | a malformed DID, an empty listing id and a bad clock are refused at issue time | `A2 a malformed DID, an empty listing id and a bad clock are refused at issue time` |
| A3 | the listing owner signature is accepted once, with a reason | `A3 the listing owner signature is accepted, once, with a reason` |
| A4 | another signer is refused | `A4 another signer is refused` |
| A5 | an expired challenge is refused | `A5 an expired challenge is refused` |
| A6 | a nonce used twice is refused as a replay | `A6 a nonce used twice is refused as a replay, and the nonce is spent exactly once` |
| A7 | a tampered DID, a rebuilt message and a tampered field are refused | `A7 a tampered DID, a rebuilt message and a tampered field are refused` |
| A8 | malformed input is refused, with a reason | `A8 malformed input is refused, with a reason` |

Branch coverage of the module is 100 percent, and the gate that proves it is in the repository:

```bash
npm install
npm run coverage:gate
```

The gate exits with code 1 when any file of the module is below 100 percent branch coverage.

## One difference from the reference chamber

The reference chamber reads the used nonce set, awaits the signature check and only then adds the
nonce. Two verifications of the same challenge that run at the same time can both pass that window.
This module takes the nonce first with `claimNonce` and gives it back with `releaseNonce` when the
signature turns out not to be the owner's, so:

- two verifications at the same time cannot both succeed (test A6),
- a failed attempt does not burn the nonce, so the owner may try again.

The behaviour of a single verification is the same as the reference, refusal by refusal, with the
same reasons.

## House rules

- Tests or it did not happen: every refusal in the contract has a test, and the coverage gate is a
  machine check.
- No secrets: the only keys in the tests are the public test keys of a local development chain. They
  are public, they hold nothing and they are never funded.
- Text people see: Latin digits, plain words, no long dashes.
- Small single concern files: `types.ts` holds the contract, `nonceStore.ts` holds the replay
  protection, `chamber1.ts` holds the rules, `index.ts` is a thin entry point.

## Running it

```bash
npm install
npm test              # node --import tsx --test test/*.test.ts
npm run test:native   # the same tests on Node 22.6 or later, without tsx
npm run coverage:gate # the tests plus the 100 percent branch coverage gate
```

## Licence

MIT. See `LICENSE`.
