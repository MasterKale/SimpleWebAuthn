import { PublicKeyCredentialRequestOptionsJSON } from '@webauthntine/typescript-types';


/**
 * Prepare a value to pass into navigator.credentials.get(...) for authenticator "login"
 *
 * @param challenge Random string the authenticator needs to sign and pass back
 * @param base64CredentialIDs Array of base64-encoded authenticator IDs registered by the user for
 * assertion
 * @param timeout How long (in ms) the user can take to complete assertion
 */
export default function generateAssertionOptions(
  challenge: string,
  base64CredentialIDs: string[],
  timeout: number = 60000,
): PublicKeyCredentialRequestOptionsJSON {
  return {
    publicKey: {
      challenge,
      allowCredentials: base64CredentialIDs.map(id => ({
        id,
        type: 'public-key',
        transports: ['usb', 'ble', 'nfc', 'internal'],
      })),
      timeout,
    },
  };
}
