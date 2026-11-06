import { SimpleWebAuthnError } from '../errors/index.ts';

/**
 * Check the RP ID to make sure it's valid to compare against what's reported in a WebAuthn
 * response.
 *
 * Invalid RP IDs will raise a `SimpleWebAuthnError` with `code: 'BAD_ARGUMENT'`
 */
export function assertValidExpectedRPID(rpID: string): void {
  const asciiRPID = new URL(`https://${rpID}`).hostname;

  if (asciiRPID !== rpID) {
    throw new SimpleWebAuthnError({
      message:
        `"${rpID}" is not a valid expected RP ID. Replace it with its ASCII punycode representation "${asciiRPID}" and try again`,
      code: 'BAD_ARGUMENT',
    });
  }
}
