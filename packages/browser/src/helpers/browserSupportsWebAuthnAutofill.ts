/* eslint-disable @typescript-eslint/ban-ts-comment */
import { PublicKeyCredentialFuture } from '@simplewebauthn/typescript-types';

/**
 * Determine if the browser supports conditional UI, so that WebAuthn credentials can
 * be shown to the user in the browser's typical password autofill popup.
 */
export async function browserSupportsWebAuthnAutofill(): Promise<boolean> {
  /**
   * I don't like the `as unknown` here but there's a `declare var PublicKeyCredential` in
   * TS' DOM lib that's making it difficult for me to just go `as PublicKeyCredentialFuture` as I
   * want. I think I'm fine with this for now since it's _supposed_ to be temporary, until TS types
   * have a chance to catch up.
   */
  const globalPublicKeyCredential =
    window.PublicKeyCredential as unknown as PublicKeyCredentialFuture;

  return (
    globalPublicKeyCredential.isConditionalMediationAvailable !== undefined &&
    globalPublicKeyCredential.isConditionalMediationAvailable()
  );
}
