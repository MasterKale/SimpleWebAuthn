/**
 * Make sure two Uint8Arrays are deeply equivalent
 */
export function areEqual(array1: Uint8Array, array2: Uint8Array): boolean {
  if (array1.length != array2.length) {
    return false;
  }

  return array1.every((val, i) => val === array2[i]);
}

/**
 * Convert a Uint8Array to Hexadecimal.
 *
 * A replacement for `Buffer.toString('hex')`
 */
export function toHex(array: Uint8Array): string {
  const hexParts = Array.from(array, i => i.toString(16).padStart(2, "0"));

  // adce000235bcc60a648b0b25f1f05503
  return hexParts.join('');
}

/**
 * Convert a Uint8Array to Base64.
 *
 * A replacement for `Buffer.toString('base64')`
 */
export function toBase64(array: Uint8Array): string {
  let str = '';

  for (const charCode of array) {
    str += String.fromCharCode(charCode);
  }

  const base64String = btoa(str);

  return base64String;
}

/**
 * Combine multiple Uint8Arrays into a single Uint8Array
 */
export function concat(arrays: Uint8Array[]): Uint8Array {
  let pointer = 0;
  const totalLength = arrays.reduce((prev, curr) => prev + curr.length, 0);

  const toReturn = new Uint8Array(totalLength);

  arrays.forEach((arr) => {
    toReturn.set(arr, pointer);
    pointer += arr.length;
  });

  return toReturn;
}

/**
 * Convert an ASCII string to Uint8Array
 */
export function fromString(value: string): Uint8Array {
  return Uint8Array.from(value.split("").map(x => x.charCodeAt(0)));
}

export default {
  areEqual,
  toHex,
  toBase64,
  concat,
  fromString,
};
