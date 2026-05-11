import { browserSupportsWebAuthn } from './browserSupportsWebAuthn.ts';
import { getBrowserCapabilities } from './getBrowserCapabilities.ts';

/**
 * Determine if the browser is capable of facilitating use of synced passkeys for **authentication**
 * via local platform authenticator or via the hybrid transport. This method does NOT know if the
 * user actually has a passkey available to use.
 */
export async function browserSupportsPasskeys(): Promise<boolean> {
  if (!browserSupportsWebAuthn()) {
    return new Promise((resolve) => resolve(false));
  }

  const capabilities = await getBrowserCapabilities();
  const {
    passkeyPlatformAuthenticator,
    userVerifyingPlatformAuthenticator,
    hybridTransport,
  } = capabilities;

  return passkeyPlatformAuthenticator === 'supported' ||
    hybridTransport === 'supported' ||
    userVerifyingPlatformAuthenticator === 'supported';
}
