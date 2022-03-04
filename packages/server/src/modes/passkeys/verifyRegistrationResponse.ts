import { } from '@simplewebauthn/typescript-types';

import _verifyRegistrationResponse, {
  VerifyRegistrationResponseOpts,
  VerifiedRegistrationResponse,
} from '../../registration/verifyRegistrationResponse';


export function verifyRegistrationResponse(
  options: VerifyRegistrationResponseOpts,
): Promise<VerifiedRegistrationResponse> {
  return _verifyRegistrationResponse({
    ...options,
    requireUserVerification: true,
  });
}
