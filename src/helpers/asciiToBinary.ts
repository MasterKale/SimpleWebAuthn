/**
 * Decode a base64-encoded string to a binary string
 *
 * @param input Base64-encoded string
 */
export default function asciiToBinary(input: string) {
  return Buffer.from(input, 'base64').toString('binary');
}
