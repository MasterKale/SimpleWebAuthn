import generateAttestationCredentials from './attestation/generateAttestationCredentials';
import verifyAttestationResponse from './attestation/verifyAttestationResponse';
import generateAssertionCredentials from './assertion/generateAssertionCredentials';

export {
  // Attestation (e.g. Registration)
  generateAttestationCredentials,
  verifyAttestationResponse,
  // Assertion (e.g. Login)
  generateAssertionCredentials,
};
