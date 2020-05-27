import type {
  PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/typescript-types';

type Options = {
  challenge: string,
  allowedBase64CredentialIDs: string[],
  suggestedTransports?: AuthenticatorTransport[],
  timeout?: number,
};

/**
 * Prepare a value to pass into navigator.credentials.get(...) for authenticator "login"
 *
 * @param challenge Random string the authenticator needs to sign and pass back
 * @param allowedBase64CredentialIDs Array of base64-encoded authenticator IDs registered by the
 * user for assertion
 * @param timeout How long (in ms) the user can take to complete assertion
 * @param suggestedTransports Suggested types of authenticators for assertion
 */
export default function generateAssertionOptions(
  opts: Options,
): PublicKeyCredentialRequestOptionsJSON {
  const {
    challenge,
    allowedBase64CredentialIDs,
    suggestedTransports = ['usb', 'ble', 'nfc', 'internal'],
    timeout = 60000,
  } = opts;

  return {
    challenge,
    allowCredentials: allowedBase64CredentialIDs.map(id => ({
      id,
      type: 'public-key',
      transports: suggestedTransports,
    })),
    timeout,
  };
}
