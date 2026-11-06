import { SimpleWebAuthnError } from '../errors/index.ts';

/**
 * Check the origin to make sure it's valid to compare against what's reported in a WebAuthn
 * response.
 *
 * Invalid origins will raise a `SimpleWebAuthnError` with `code: 'BAD_ARGUMENT'`
 */
export function assertValidExpectedOrigin(origin: string): void {
  // We might be dealing with an exotic origin, like an application package identifier
  if (!origin.startsWith('https://')) {
    return;
  }

  // Reject an expected origin that includes a trailing slash (e.g. "https://example.com/")
  if (origin.endsWith('/')) {
    throw new SimpleWebAuthnError({
      message: `"${origin}" is not a valid expected origin. Remove the trailing "/" and try again`,
      code: 'BAD_ARGUMENT',
    });
  }

  // Reject an expected origin that includes UTF-8 characters (e.g. "https://ëxämplë.com")
  const asciiOrigin = new URL(origin).origin;

  if (asciiOrigin !== origin) {
    throw new SimpleWebAuthnError({
      message:
        `"${origin}" is not a valid expected origin. Replace it with its ASCII punycode representation "${asciiOrigin}" and try again`,
      code: 'BAD_ARGUMENT',
    });
  }
}
