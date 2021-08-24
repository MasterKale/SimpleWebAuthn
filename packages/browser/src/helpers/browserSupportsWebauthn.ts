/**
 * Determine if the browser is capable of Webauthn
 */
export function browserSupportsWebauthn(): boolean {
  return (
    window?.PublicKeyCredential !== undefined && typeof window.PublicKeyCredential === 'function'
  );
}
