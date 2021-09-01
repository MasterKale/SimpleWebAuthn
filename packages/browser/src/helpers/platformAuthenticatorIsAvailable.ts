import { browserSupportsWebauthn } from './browserSupportsWebauthn';

/**
 * Determine whether the browser can communicate with a built-in authenticator, like
 * Touch ID, Android fingerprint scanner, or Windows Hello.
 *
 * This method will _not_ be able to tell you the name of the platform authenticator.
 */
export async function platformAuthenticatorIsAvailable(): Promise<boolean> {
  if (!browserSupportsWebauthn()) {
    return false;
  }

  return PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
}
