/**
 * A runtime-agnostic collection of methods for working with Base64URL encoding
 * @module
 */
import base64 from '@hexagon/base64';

import type { Base64URLString, Uint8Array_ } from '../../types/index.ts';

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
): Uint8Array_ {
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
export function fromBuffer(
  buffer: Uint8Array_,
  to: 'base64' | 'base64url' = 'base64url',
): string {
  /**
   * Gracefully handle Uint8Array subclass types, like Node's Buffer, that can have a large
   * ArrayBuffer backing it.
   */
  const _normalized = new Uint8Array(buffer);
  return base64.fromArrayBuffer(_normalized.buffer, to === 'base64url');
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
 * Encode a UTF-8 string to base64url
 */
export function fromUTF8String(utf8String: string): string {
  return base64.fromString(utf8String, true);
}

/**
 * Decode a base64url string into its original UTF-8 string
 */
export function toUTF8String(base64urlString: string): string {
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
export function isBase64URL(input: string): boolean {
  // Trim padding characters from the string if present
  input = trimPadding(input);
  return base64.validate(input, true);
}

/**
 * Remove optional padding from a base64url-encoded string
 */
export function trimPadding(input: Base64URLString): Base64URLString {
  return input.replace(/=/g, '');
}
