import { SimpleWebAuthnError } from '../errors/index.ts';

/**
 * Check the origin to make sure it's in an ASCII representation (a.k.a. punycode).
 *
 * UTF-8 strings will raise a `SimpleWebAuthnError` with `code: 'BAD_ARGUMENT'`
 */
export function assertASCIIOrigin(origin: string): void {
  // We might be dealing with an exotic origin, like an application package identifier
  if (!origin.startsWith('https://')) {
    return;
  }

  const asciiOrigin = new URL(origin).origin;

  if (asciiOrigin !== origin) {
    throw new SimpleWebAuthnError({
      message:
        `"${origin}" is not a valid expected origin. Replace it with its ASCII punycode representation "${asciiOrigin}" and try again`,
      code: 'BAD_ARGUMENT',
    });
  }
}
