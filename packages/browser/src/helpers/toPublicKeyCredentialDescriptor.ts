import type { PublicKeyCredentialDescriptorJSON } from '@simplewebauthn/typescript-types';

import { base64URLStringToBuffer } from './base64URLStringToBuffer';

export function toPublicKeyCredentialDescriptor(
  descriptor: PublicKeyCredentialDescriptorJSON,
): PublicKeyCredentialDescriptor {
  const { id } = descriptor;

  return {
    ...descriptor,
    id: base64URLStringToBuffer(id),
    /**
     * `descriptor.transports` is an array of our `AuthenticatorTransport` that includes newer
     * transports that TypeScript's DOM lib is ignorant of. Convince TS that our list of transports
     * are fine to pass to WebAuthn since browsers will recognize the new value.
     */
    transports: descriptor.transports as AuthenticatorTransport[],
  };
}
