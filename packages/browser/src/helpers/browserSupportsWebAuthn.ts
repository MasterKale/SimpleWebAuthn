/**
 * Determine if the browser is capable of Webauthn
 */
export function browserSupportsWebAuthn(): boolean {
  return (
    globalThis?.PublicKeyCredential !== undefined &&
    typeof globalThis.PublicKeyCredential === 'function'
  );
}
