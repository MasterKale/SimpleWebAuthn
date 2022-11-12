import { webcrypto } from 'node:crypto';

/**
 * Generate a suitably random value to be used as an attestation or assertion challenge
 */
export function generateChallenge(): Uint8Array {
  /**
   * WebAuthn spec says that 16 bytes is a good minimum:
   *
   * "In order to prevent replay attacks, the challenges MUST contain enough entropy to make
   * guessing them infeasible. Challenges SHOULD therefore be at least 16 bytes long."
   *
   * Just in case, let's double it
   */
  const challenge = new Uint8Array(32);

  if (globalThis.crypto) {
    // We're in a browser-like runtime, use global Crypto
    globalThis.crypto.getRandomValues(challenge);
  } else {
    // We're in Node, use Node's Crypto
    webcrypto.getRandomValues(challenge);
  }

  return challenge;
}
