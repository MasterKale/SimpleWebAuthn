import type { AuthenticatorDevice } from '@simplewebauthn/typescript-types';

/**
 * You'll need a database to store a few things:
 *
 * 1. Users
 *
 * You'll need to be able to associate registration and authentications challenges, and
 * authenticators to a specific user. See `LoggedInUser` below for an idea of the minimum amount of
 * info you'll need to track for a specific user during these flows.
 *
 * 2. Challenges
 *
 * The totally-random-unique-every-time values you pass into every execution of
 * `generateRegistrationOptions()` or `generateAuthenticationOptions()` MUST be stored until
 * `verifyRegistrationResponse()` or `verifyAuthenticationResponse()` (respectively) is called to verify
 * that the response contains the signed challenge.
 *
 * These values only need to be persisted for `timeout` number of milliseconds (see the `generate`
 * methods and their optional `timeout` parameter)
 *
 * 3. Authenticator Devices
 *
 * After registration, you'll need to store three things about the authenticator:
 *
 * - Base64-encoded "Credential ID" (varchar)
 * - Base64-encoded "Public Key" (varchar)
 * - Counter (int)
 *
 * Each authenticator must also be associated to a user so that you can generate a list of
 * authenticator credential IDs to pass into `generateAuthenticationOptions()`, from which one is
 * expected to generate an authentication response.
 */
interface LoggedInUser {
  id: string;
  username: string;
  devices: AuthenticatorDevice[];
}

declare module 'express-session' {
  interface SessionData {
    /**
     * A simple way of storing a user's current challenge being signed by registration or authentication.
     * It should be expired after `timeout` milliseconds (optional argument for `generate` methods,
     * defaults to 60000ms)
     */
    currentChallenge?: string;
  }
}
