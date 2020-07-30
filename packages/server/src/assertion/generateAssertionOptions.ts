import type {
  PublicKeyCredentialRequestOptionsJSON,
  Base64URLString,
} from '@simplewebauthn/typescript-types';
import base64url from 'base64url';

import generateChallenge from '../helpers/generateChallenge';

type Options = {
  allowedCredentialIDs: Base64URLString[];
  challenge?: string | Buffer;
  suggestedTransports?: AuthenticatorTransport[];
  timeout?: number;
  userVerification?: UserVerificationRequirement;
  extensions?: AuthenticationExtensionsClientInputs;
};

/**
 * Prepare a value to pass into navigator.credentials.get(...) for authenticator "login"
 *
 * @param allowedCredentialIDs Array of base64url-encoded authenticator IDs registered by the
 * @param challenge Random string the authenticator needs to sign and pass back
 * user for assertion
 * @param timeout How long (in ms) the user can take to complete assertion
 * @param suggestedTransports Suggested types of authenticators for assertion
 * @param userVerification Set to `'discouraged'` when asserting as part of a 2FA flow, otherwise
 * set to `'preferred'` or `'required'` as desired.
 * @param extensions Additional plugins the authenticator or browser should use during assertion
 */
export default function generateAssertionOptions(
  options: Options,
): PublicKeyCredentialRequestOptionsJSON {
  const {
    allowedCredentialIDs,
    challenge = generateChallenge(),
    suggestedTransports = ['usb', 'ble', 'nfc', 'internal'],
    timeout = 60000,
    userVerification,
    extensions,
  } = options;

  return {
    challenge: base64url.encode(challenge),
    allowCredentials: allowedCredentialIDs.map(id => ({
      id,
      type: 'public-key',
      transports: suggestedTransports,
    })),
    timeout,
    userVerification,
    extensions,
  };
}
