/**
 * A helper method to convert an arbitrary string sent from the server to a Uint8Array the
 * authenticator will expect.
 */
export default function toUint8Array(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}
