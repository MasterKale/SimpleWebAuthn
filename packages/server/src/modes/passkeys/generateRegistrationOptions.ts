import {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialDescriptor,
} from '@simplewebauthn/typescript-types';

import _generateRegistrationOptions from '../../registration/generateRegistrationOptions';


/**
 *
 * @param options.rpID Valid domain name (after `https://`)
 * @param options.userID Website's unique ID for the user (uuid, etc...)
 * @param options.userName User's display name (email, etc...)
 * @param options.userRegisteredCredentials The user's existing credentials. Prevents existing users
 * from re-enrolling an authenticator and locking themselves out of their account
 */
export function generateRegistrationOptions(options: {
  rpID: string,
  userID: string,
  userName: string,
  userRegisteredCredentials: PublicKeyCredentialDescriptor[],
}): PublicKeyCredentialCreationOptionsJSON {
  const {
    rpID,
    userID,
    userName,
    userRegisteredCredentials,
  } = options;

  return _generateRegistrationOptions({
    rpID,
    rpName: rpID,
    userID,
    userName,
    authenticatorSelection: {
      userVerification: 'required',
      residentKey: 'required',
    },
    attestationType: 'none',
    excludeCredentials: userRegisteredCredentials,
    // ES256 and RS256
    supportedAlgorithmIDs: [-7, -257],
    userDisplayName: userName,
  });
}
