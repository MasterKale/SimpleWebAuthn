/**
 * Determine if the browser is capable of Webauthn
 */
export default function supportsWebauthn(): boolean {
  return (
    window?.PublicKeyCredential !== undefined
    && typeof window.PublicKeyCredential === 'function'
  );
}
