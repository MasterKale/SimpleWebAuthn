import {
  RegistrationCredentialJSON,
} from '@simplewebauthn/typescript-types';

import _verifyRegistrationResponse, {
  VerifiedRegistrationResponse,
} from '../../registration/verifyRegistrationResponse';


export function verifyRegistrationResponse(
  options: {
    credential: RegistrationCredentialJSON;
    expectedChallenge: string | ((challenge: string) => boolean);
    expectedOrigin: string | string[];
    expectedRPID: string | string[];
  },
): Promise<VerifiedRegistrationResponse> {
  const { credential, expectedChallenge, expectedOrigin, expectedRPID } = options;
  return _verifyRegistrationResponse({
    credential,
    expectedChallenge,
    expectedOrigin,
    expectedRPID,
    requireUserVerification: true,
    supportedAlgorithmIDs: [-7, -257],
  });
}
