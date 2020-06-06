import base64url from 'base64url';

/**
 * Decode an authenticator's base64url-encoded clientDataJSON to JSON
 */
export default function decodeClientDataJSON(data: string): ClientDataJSON {
  const toString = base64url.decode(data);
  const clientData: ClientDataJSON = JSON.parse(toString);

  // `challenge` will be Base64URL-encoded here. Decode it for easier comparisons with what is
  // provided as the expected value
  clientData.challenge = base64url.decode(clientData.challenge);

  return clientData;
}

type ClientDataJSON = {
  type: string;
  challenge: string;
  origin: string;
};
