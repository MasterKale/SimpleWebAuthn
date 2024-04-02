import { PublicKeyCredentialFuture } from "@simplewebauthn/types";

import { browserSupportsWebAuthn } from "./browserSupportsWebAuthn";

/**
 * Determine if the browser supports conditional UI, so that WebAuthn credentials can
 * be shown to the user in the browser's typical password autofill popup.
 */
export function browserSupportsWebAuthnAutofill(): Promise<boolean> {
  if (!browserSupportsWebAuthn()) {
    return new Promise((resolve) => resolve(false));
  }

  /**
   * I don't like the `as unknown` here but there's a `declare var PublicKeyCredential` in
   * TS' DOM lib that's making it difficult for me to just go `as PublicKeyCredentialFuture` as I
   * want. I think I'm fine with this for now since it's _supposed_ to be temporary, until TS types
   * have a chance to catch up.
   */
  const globalPublicKeyCredential = window
    .PublicKeyCredential as unknown as PublicKeyCredentialFuture;

  if (globalPublicKeyCredential.isConditionalMediationAvailable === undefined) {
    return new Promise((resolve) => resolve(false));
  }

  return globalPublicKeyCredential.isConditionalMediationAvailable();
}
