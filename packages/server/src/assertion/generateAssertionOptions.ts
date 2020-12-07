import type { PublicKeyCredentialRequestOptionsJSON } from '@simplewebauthn/typescript-types';
import base64url from 'base64url';
import { GenerateAssertionOptions } from './options';

import generateChallenge from '../helpers/generateChallenge';

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
  options: GenerateAssertionOptions,
): PublicKeyCredentialRequestOptionsJSON {
  const {
    allowCredentials,
    challenge = generateChallenge(),
    timeout = 60000,
    userVerification,
    extensions,
    rpID,
    adapters,
  } = options;

  const base64Challenge = base64url.encode(challenge);

  const response = {
    challenge: base64Challenge,
    allowCredentials,
    timeout,
    userVerification,
    extensions,
    rpId: rpID,
  };

  if (!adapters) return response;

  return adapters.reduce<PublicKeyCredentialRequestOptionsJSON>(
    (acc, adapter) => adapter.assert(acc),
    response,
  );
}
