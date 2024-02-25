import type {
  AuthenticationExtensionsClientInputs,
  AuthenticatorTransportFuture,
  Base64URLString,
  PublicKeyCredentialRequestOptionsJSON,
  UserVerificationRequirement,
} from '../deps.ts';
import { isoBase64URL, isoUint8Array } from '../helpers/iso/index.ts';
import { generateChallenge } from '../helpers/generateChallenge.ts';

export type GenerateAuthenticationOptionsOpts = {
  allowCredentials?: {
    id: Base64URLString;
    transports?: AuthenticatorTransportFuture[];
  }[];
  challenge?: string | Uint8Array;
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
export async function generateAuthenticationOptions(
  options: GenerateAuthenticationOptionsOpts = {},
): Promise<PublicKeyCredentialRequestOptionsJSON> {
  const {
    allowCredentials,
    challenge = await generateChallenge(),
    timeout = 60000,
    userVerification = 'preferred',
    extensions,
    rpID,
  } = options;

  /**
   * Preserve ability to specify `string` values for challenges
   */
  let _challenge = challenge;
  if (typeof _challenge === 'string') {
    _challenge = isoUint8Array.fromUTF8String(_challenge);
  }

  return {
    challenge: isoBase64URL.fromBuffer(_challenge),
    allowCredentials: allowCredentials?.map((cred) => {
      if (!isoBase64URL.isBase64URL(cred.id)) {
        throw new Error(`excludeCredential id "${cred.id}" is not a valid base64url string`);
      }

      return {
        ...cred,
        id: isoBase64URL.trimPadding(cred.id),
        type: 'public-key',
      };
    }),
    timeout,
    userVerification,
    extensions,
    rpId: rpID,
  };
}
