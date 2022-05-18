import type {
  AuthenticationExtensionsClientInputs,
  PublicKeyCredentialRequestOptionsJSON,
  PublicKeyCredentialDescriptorFuture,
  UserVerificationRequirement,
} from '@simplewebauthn/typescript-types';
import base64url from 'base64url';

import generateChallenge from '../helpers/generateChallenge';

export type GenerateAuthenticationOptionsOpts = {
  allowCredentials?: PublicKeyCredentialDescriptorFuture[];
  challenge?: string | Buffer;
  timeout?: number;
  userVerification?: UserVerificationRequirement;
  extensions?: AuthenticationExtensionsClientInputs;
  rpID?: string;
};

/**
 * Prepare a value to pass into navigator.credentials.get(...) for authenticator "login"
 *
 * @param allowCredentials Authenticators previously registered by the user, if any. If undefined
 * the client will ask the user which credential they want to use
 * @param challenge Random value the authenticator needs to sign and pass back
 * user for authentication
 * @param timeout How long (in ms) the user can take to complete authentication
 * @param userVerification Set to `'discouraged'` when asserting as part of a 2FA flow, otherwise
 * set to `'preferred'` or `'required'` as desired.
 * @param extensions Additional plugins the authenticator or browser should use during authentication
 * @param rpID Valid domain name (after `https://`)
 */
export default function generateAuthenticationOptions(
  options: GenerateAuthenticationOptionsOpts = {},
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
    allowCredentials: allowCredentials?.map(cred => ({
      ...cred,
      id: base64url.encode(cred.id as Buffer),
    })),
    timeout,
    userVerification,
    extensions,
    rpId: rpID,
  };
}
