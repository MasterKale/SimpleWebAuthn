// Base64URL, with optional padding
const base64urlRegEx = /^([0-9a-zA-Z-_]{4})*(([0-9a-zA-Z-_]{2}(==)?)|([0-9a-zA-Z-_]{3}=?))?$/;

/**
 * Check to see if a string only contains valid Base64URL values
 */
export function isBase64URLString(value: string): boolean {
  if (!value) {
    return false;
  }

  return base64urlRegEx.test(value);
}
