/**
 * A helper method to convert a string sent from the server to a Uint8Array the authenticator will
 * expect.
 */
export default function toUint8Array(value: string): Uint8Array {
  return Uint8Array.from(value, c => c.charCodeAt(0));
}
