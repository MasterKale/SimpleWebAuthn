import type { Base64URLString } from '@simplewebauthn/types';

import { isoBase64URL } from './iso/index.ts';

/**
 * Decode an authenticator's base64url-encoded clientDataJSON to JSON
 */
export function decodeClientDataJSON(data: Base64URLString): ClientDataJSON {
  const toString = isoBase64URL.toUTF8String(data);
  const clientData: ClientDataJSON = JSON.parse(toString);

  return _decodeClientDataJSONInternals.stubThis(clientData);
}

export type ClientDataJSON = {
  type: string;
  challenge: string;
  origin: string;
  crossOrigin?: boolean;
  tokenBinding?: {
    id?: string;
    status: 'present' | 'supported' | 'not-supported';
  };
};

// Make it possible to stub the return value during testing
export const _decodeClientDataJSONInternals = {
  stubThis: (value: ClientDataJSON) => value,
};
