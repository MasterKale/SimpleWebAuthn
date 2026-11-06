import { SimpleWebAuthnError } from '../errors/index.ts';
import { assertASCIIOrigin } from './assertASCIIOrigin.ts';

/**
 * Check that the origin reported in a WebAuthn response is an expected one.
 *
 * Raises a `SimpleWebAuthnError` if not match is found.
 */
export function matchExpectedOrigin(origin: string, expectedOrigin: string | string[]) {
  let _expectedOrigins: string[] = [];
  if (typeof expectedOrigin === 'string') {
    _expectedOrigins = [expectedOrigin];
  } else {
    _expectedOrigins = expectedOrigin;
  }

  for (const _origin of _expectedOrigins) {
    assertASCIIOrigin(_origin);
  }

  if (!_expectedOrigins.includes(origin)) {
    throw new SimpleWebAuthnError({
      message: `Unexpected response origin "${origin}", expected one of: ${
        _expectedOrigins.join(
          ', ',
        )
      }`,
      code: 'UNEXPECTED_ORIGIN',
    });
  }
}
