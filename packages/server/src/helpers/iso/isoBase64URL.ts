import base64 from '@hexagon/base64';

/**
 * Decode from a Base64URL-encoded string to an ArrayBuffer. Best used when converting a
 * credential ID from a JSON string to an ArrayBuffer, like in allowCredentials or
 * excludeCredentials.
 *
 * @param buffer Value to decode from base64
 * @param to (optional) The decoding to use, in case it's desirable to decode from base64 instead
 */
export function toBuffer(
  base64urlString: string,
  from: 'base64' | 'base64url' = 'base64url',
): Uint8Array {
  const _buffer = base64.toArrayBuffer(base64urlString, from === 'base64url');
  return new Uint8Array(_buffer);
}

/**
 * Encode the given array buffer into a Base64URL-encoded string. Ideal for converting various
 * credential response ArrayBuffers to string for sending back to the server as JSON.
 *
 * @param buffer Value to encode to base64
 * @param to (optional) The encoding to use, in case it's desirable to encode to base64 instead
 */
export function fromBuffer(buffer: Uint8Array, to: 'base64' | 'base64url' = 'base64url'): string {
  return base64.fromArrayBuffer(buffer, to === 'base64url');
}

/**
 * Convert a base64url string into base64
 */
export function toBase64(base64urlString: string): string {
  const fromBase64Url = base64.toArrayBuffer(base64urlString, true);
  const toBase64 = base64.fromArrayBuffer(fromBase64Url);
  return toBase64;
}

/**
 * Encode a string to base64url
 */
export function fromString(ascii: string): string {
  return base64.fromString(ascii, true);
}

/**
 * Decode a base64url string into its original string
 */
export function toString(base64urlString: string): string {
  return base64.toString(base64urlString, true);
}

/**
 * Confirm that the string is encoded into base64
 */
export function isBase64(input: string): boolean {
  return base64.validate(input, false);
}

/**
 * Confirm that the string is encoded into base64url, with support for optional padding
 */
export function isBase64url(input: string): boolean {
  // Trim padding characters from the string if present
  input = input.replace(/=/g, '');
  return base64.validate(input, true);
}
