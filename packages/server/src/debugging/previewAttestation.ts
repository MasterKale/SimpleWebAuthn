import { AttestationCredentialJSON } from '@simplewebauthn/typescript-types';
import decodeClientDataJSON, { ClientDataJSON } from '../helpers/decodeClientDataJSON';
import decodeAttestationObject, {
  AttestationStatement,
  ATTESTATION_FORMATS,
} from '../helpers/decodeAttestationObject';
import parseAuthenticatorData, { AuthenticatorData } from '../helpers/parseAuthenticatorData';

/**
 * Parse and decode an attestation credential into a human-friendlier JSON structure
 */
export default function previewAttestation(
  credential: AttestationCredentialJSON,
): AttestationPreview {
  const { response } = credential;

  const clientDataJSON = decodeClientDataJSON(response.clientDataJSON);
  const attestationObject = decodeAttestationObject(response.attestationObject);
  const authData = parseAuthenticatorData(attestationObject.authData);

  return {
    ...credential,
    response: {
      clientDataJSON,
      attestationObject: {
        ...attestationObject,
        authData,
      },
    },
  };
}

export type AttestationPreview = {
  id: string;
  rawId: string;
  response: {
    clientDataJSON: ClientDataJSON;
    attestationObject: {
      authData: AuthenticatorData;
      fmt: ATTESTATION_FORMATS;
      attStmt: AttestationStatement;
    };
  };
  type: string;
};
