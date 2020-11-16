import type { AuthenticatorDevice } from '@simplewebauthn/typescript-types';

/**
 * You'll need a database to store a few things:
 *
 * 1. Users
 *
 * You'll need to be able to associate attestation and assertions challenges, and authenticators to
 * a specific user
 *
 * 2. Challenges
 *
 * The totally-random-unique-every-time values you pass into every execution of
 * `generateAttestationOptions()` or `generateAssertionOptions()` MUST be stored until
 * `verifyAttestationResponse()` or `verifyAssertionResponse()` (respectively) is called to verify
 * that the response contains the signed challenge.
 *
 * These values only need to be persisted for `timeout` number of milliseconds (see the `generate`
 * methods and their optional `timeout` parameter)
 *
 * 3. Authenticator Devices
 *
 * After an attestation, you'll need to store three things about the authenticator:
 *
 * - Base64-encoded "Credential ID" (varchar)
 * - Base64-encoded "Public Key" (varchar)
 * - Counter (int)
 *
 * Each authenticator must also be associated to a user so that you can generate a list of
 * authenticator credential IDs to pass into `generateAssertionOptions()`, from which one is
 * expected to generate an assertion response.
 */
interface LoggedInUser {
  id: string;
  username: string;
  devices: AuthenticatorDevice[];
  currentChallenge?: string;
}
