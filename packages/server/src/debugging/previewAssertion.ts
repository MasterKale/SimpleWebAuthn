import base64url from 'base64url';

import { AssertionCredentialJSON } from '@simplewebauthn/typescript-types';
import decodeClientDataJSON, { ClientDataJSON } from '../helpers/decodeClientDataJSON';
import parseAuthenticatorData, { AuthenticatorData } from '../helpers/parseAuthenticatorData';

/**
 * Parse and decode an assertion credential into a human-friendlier JSON structure
 */
export default function previewAttestation(
  credential: AssertionCredentialJSON,
): AttestationPreview {
  const { response } = credential;

  const clientDataJSON = decodeClientDataJSON(response.clientDataJSON);
  const authDataBuffer = base64url.toBuffer(response.authenticatorData);
  const authenticatorData = parseAuthenticatorData(authDataBuffer);

  return {
    ...credential,
    response: {
      ...response,
      clientDataJSON,
      authenticatorData,
    },
  };
}

export type AttestationPreview = {
  id: string;
  rawId: string;
  response: {
    clientDataJSON: ClientDataJSON;
    authenticatorData: AuthenticatorData;
    signature: string;
    userHandle?: string;
  };
  type: string;
};
