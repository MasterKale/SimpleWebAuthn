/**
 * A helper method to convert an arbitrary ArrayBuffer, returned from an authenticator, to a UTF-8
 * string.
 */
export function bufferToUTF8String(value: ArrayBuffer): string {
  return new TextDecoder('utf-8').decode(value);
}
