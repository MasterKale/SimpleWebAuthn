import base64url from 'base64url';
import { AttestationCredentialJSON, Base64URLString } from '@simplewebauthn/typescript-types';

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

  let credentialID = undefined;
  if (authData.credentialID) {
    credentialID = base64url.encode(authData.credentialID);
  }

  let credentialPublicKey = undefined;
  if (authData.credentialPublicKey) {
    credentialPublicKey = base64url.encode(authData.credentialPublicKey);
  }

  return {
    ...credential,
    response: {
      clientDataJSON,
      attestationObject: {
        ...attestationObject,
        authData: {
          ...authData,
          credentialID,
          credentialPublicKey,
        },
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
      authData: AuthenticatorDataPreview;
      fmt: ATTESTATION_FORMATS;
      attStmt: AttestationStatement;
    };
  };
  type: string;
};

/**
 * AuthenticatorData with a handful of the interesting Buffers converted to something more
 * human-friendly
 */
interface AuthenticatorDataPreview
  extends Omit<AuthenticatorData, 'credentialID' | 'credentialPublicKey'> {
  credentialID?: Base64URLString;
  credentialPublicKey?: Base64URLString;
}
