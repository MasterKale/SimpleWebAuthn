import type {
  AuthenticationExtensionsClientInputs,
  PublicKeyCredentialRequestOptionsJSON,
  PublicKeyCredentialRequestOptionsJSONWithSignedChallenge,
  PublicKeyCredentialDescriptorJSON,
  UserVerificationRequirement,
} from '@simplewebauthn/typescript-types';
import base64url from 'base64url';
import signChallenge from '../helpers/signChallenge';

import generateChallenge from '../helpers/generateChallenge';

interface Options {
  allowCredentials: PublicKeyCredentialDescriptorJSON[];
  challenge?: string | Buffer;
  timeout?: number;
  userVerification?: UserVerificationRequirement;
  extensions?: AuthenticationExtensionsClientInputs;
  rpID?: string;
}

interface OptionsWithServerSecret extends Omit<Options, 'rpID'> {
  serverSecret: string;
  rpID: string;
  origin: string;
}

export default function generateAssertionOptions(
  options: Options,
): PublicKeyCredentialRequestOptionsJSON;

export default function generateAssertionOptions(
  options: OptionsWithServerSecret,
): PublicKeyCredentialRequestOptionsJSONWithSignedChallenge;

/**
 * Prepare a value to pass into navigator.credentials.get(...) for authenticator "login"
 *
 * @param allowCredentials Authenticators previously registered by the user
 * @param challenge Random value the authenticator needs to sign and pass back
 * user for assertion
 * @param timeout How long (in ms) the user can take to complete assertion
 * @param userVerification Set to `'discouraged'` when asserting as part of a 2FA flow, otherwise
 * set to `'preferred'` or `'required'` as desired.
 * @param extensions Additional plugins the authenticator or browser should use during assertion
 * @param rpID Valid domain name (after `https://`)
 * @param serverSecret A global random string with at least 64 chars (from env vars for example)
 * to avoid storing the challenge into your DB, and enable stateless challenge validation
 */
export default function generateAssertionOptions(
  options: OptionsWithServerSecret | Options,
):
  | PublicKeyCredentialRequestOptionsJSON
  | PublicKeyCredentialRequestOptionsJSONWithSignedChallenge {
  const {
    allowCredentials,
    challenge = generateChallenge(),
    timeout = 60000,
    userVerification,
    extensions,
    rpID,
    serverSecret,
    origin,
  } = options as OptionsWithServerSecret;

  const base64Challenge = base64url.encode(challenge);
  return {
    challenge: base64Challenge,
    signedChallenge: signChallenge({ challenge: base64Challenge, rpID, origin }, serverSecret),
    allowCredentials,
    timeout,
    userVerification,
    extensions,
    rpId: rpID,
  };
}
