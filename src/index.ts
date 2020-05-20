import generateAttestationCredentials from './attestation/generateAttestationCredentials';
import verifyAttestationResponse from './attestation/verifyAttestationResponse';
import generateAssertionCredentials from './assertion/generateAssertionCredentials';
import verifyAssertionResponse from './assertion/verifyAssertionResponse';

export {
  generateAssertionCredentials,
  verifyAttestationResponse,
  generateAttestationCredentials,
  verifyAssertionResponse,
};

export {
  EncodedAuthenticatorAssertionResponse,
  EncodedAuthenticatorAttestationResponse,
  VerifiedAttestation,
  VerifiedAssertion,
  AuthenticatorDevice,
} from './libTypes';
