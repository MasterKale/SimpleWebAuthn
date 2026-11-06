import { SimpleWebAuthnError } from '../errors/index.ts';

/**
 * Check the RP ID to make sure it's in an ASCII representation (a.k.a. punycode).
 *
 * UTF-8 strings will raise a `SimpleWebAuthnError` with `code: 'BAD_ARGUMENT'`
 */
export function assertASCIIRPID(rpID: string): void {
  const asciiRPID = new URL(`https://${rpID}`).hostname;

  if (asciiRPID !== rpID) {
    throw new SimpleWebAuthnError({
      message:
        `"${rpID}" is not a valid expected RP ID. Replace it with its ASCII punycode representation "${asciiRPID}" and try again`,
      code: 'BAD_ARGUMENT',
    });
  }
}
