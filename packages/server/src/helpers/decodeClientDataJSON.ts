import type { ClientDataJSON } from '@webauthntine/typescript-types';
import asciiToBinary from './asciiToBinary';

/**
 * Decode an authenticator's base64-encoded clientDataJSON to JSON
 */
export default function decodeClientDataJSON(data: string): ClientDataJSON {
  const toString = asciiToBinary(data);
  const clientData: ClientDataJSON = JSON.parse(toString);

  // `challenge` will be Base64-encoded here. Decode it for easier comparisons with what is provided
  // as the expected value
  clientData.challenge = Buffer.from(clientData.challenge, 'base64').toString('ascii');

  return clientData;
}
