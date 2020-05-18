import { ClientDataJSON } from '@types';

import asciiToBinary from './asciiToBinary';

/**
 * Decode an authenticator's base64-encoded clientDataJSON to JSON
 *
 * @param data
 * @returns {Object} - the data as JSON
 */
export default function decodeClientDataJSON(data: string): ClientDataJSON {
  const toString = asciiToBinary(data);
  return JSON.parse(toString);
}
