/* eslint-disable @typescript-eslint/ban-ts-comment */
import * as cborx from 'cbor-x';

/**
 * This encoder should keep CBOR data the same length when data is re-encoded
 *
 * MOST CRITICALLY, this means the following needs to be true of whatever CBOR library we use:
 * - CBOR Map type values MUST decode to JavaScript Maps
 * - CBOR tag 64 (uint8 Typed Array) MUST NOT be used when encoding Uint8Arrays back to CBOR
 *
 * So long as these requirements are maintained, then CBOR sequences can be encoded and decoded
 * freely while maintaining their lengths for the most accurate pointer movement across them.
 */
const encoder = new cborx.Encoder({ mapsAsObjects: false, tagUint8Array: false });

/**
 * Decode and return the first item in a sequence of CBOR-encoded values
 *
 * @param input The CBOR data to decode
 * @param asObject (optional) Whether to convert any CBOR Maps into JavaScript Objects. Defaults to
 * `false`
 */
export function decodeFirst<Type>(input: Uint8Array): Type {
  const decoded = encoder.decodeMultiple(input) as undefined | Type[];

  if (decoded === undefined) {
    throw new Error('CBOR input data was empty');
  }

  /**
   * Typing on `decoded` is `void | []` which causes TypeScript to think that it's an empty array,
   * and thus you can't destructure it. I'm ignoring that because the code works fine in JS, and
   * so this should be a valid operation.
   */
  // @ts-ignore 2493
  const [first] = decoded;

  return first;
}

/**
 * Encode data to CBOR
 */
export function encode(input: any): Uint8Array {
  return encoder.encode(input);
}
