import type {
  AuthenticationExtensionsClientInputs,
  PublicKeyCredentialRequestOptionsJSON,
  PublicKeyCredentialDescriptorJSON,
  UserVerificationRequirement,
} from '@simplewebauthn/typescript-types';
import base64url from 'base64url';

import generateChallenge from '../helpers/generateChallenge';

type Options = {
  allowCredentials?: PublicKeyCredentialDescriptorJSON[];
  challenge?: string | Buffer;
  timeout?: number;
  userVerification?: UserVerificationRequirement;
  extensions?: AuthenticationExtensionsClientInputs;
  rpID?: string;
};

/**
 * Prepare a value to pass into navigator.credentials.get(...) for authenticator "login"
 *
 * @param allowCredentials Authenticators previously registered by the user, if not provided
 * device can ask user which credential he wants to use
 * @param challenge Random value the authenticator needs to sign and pass back
 * user for assertion
 * @param timeout How long (in ms) the user can take to complete assertion
 * @param userVerification Set to `'discouraged'` when asserting as part of a 2FA flow, otherwise
 * set to `'preferred'` or `'required'` as desired.
 * @param extensions Additional plugins the authenticator or browser should use during assertion
 * @param rpID Valid domain name (after `https://`)
 */
export default function generateAssertionOptions(
  options: Options = {},
): PublicKeyCredentialRequestOptionsJSON {
  const {
    allowCredentials,
    challenge = generateChallenge(),
    timeout = 60000,
    userVerification,
    extensions,
    rpID,
  } = options;

  return {
    challenge: base64url.encode(challenge),
    allowCredentials,
    timeout,
    userVerification,
    extensions,
    rpId: rpID,
  };
}
