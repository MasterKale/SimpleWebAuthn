/* eslint-disable @typescript-eslint/ban-ts-comment */
import * as cborx from 'cbor-x';

export function decodeCborFirst(input: Uint8Array): any {
  const decoded = cborx.decodeMultiple(input);

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
