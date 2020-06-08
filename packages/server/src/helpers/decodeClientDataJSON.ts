import base64url from 'base64url';

/**
 * Decode an authenticator's base64url-encoded clientDataJSON to JSON
 */
export default function decodeClientDataJSON(data: string): ClientDataJSON {
  const toString = base64url.decode(data);
  const clientData: ClientDataJSON = JSON.parse(toString);

  return clientData;
}

type ClientDataJSON = {
  type: string;
  challenge: string;
  origin: string;
  crossOrigin?: boolean;
  tokenBinding?: {
    id?: string;
    status: 'present' | 'supported' | 'not-supported';
  };
};
