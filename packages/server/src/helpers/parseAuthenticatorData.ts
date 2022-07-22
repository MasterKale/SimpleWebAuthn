import cbor from 'cbor';
import { decodeCborFirst } from './decodeCbor';
import { decodeAuthenticatorExtensions, AuthenticationExtensionsAuthenticatorOutputs } from './decodeAuthenticatorExtensions';

/**
 * Make sense of the authData buffer contained in an Attestation
 */
export default function parseAuthenticatorData(authData: Buffer): ParsedAuthenticatorData {
  if (authData.byteLength < 37) {
    throw new Error(
      `Authenticator data was ${authData.byteLength} bytes, expected at least 37 bytes`,
    );
  }

  let pointer = 0;

  const rpIdHash = authData.slice(pointer, (pointer += 32));

  const flagsBuf = authData.slice(pointer, (pointer += 1));
  const flagsInt = flagsBuf[0];

  // Bit positions can be referenced here:
  // https://www.w3.org/TR/webauthn-2/#flags
  const flags = {
    up: !!(flagsInt & 1 << 0), // User Presence
    uv: !!(flagsInt & 1 << 2), // User Verified
    be: !!(flagsInt & 1 << 3), // Backup Eligibility
    bs: !!(flagsInt & 1 << 4), // Backup State
    at: !!(flagsInt & 1 << 6), // Attested Credential Data Present
    ed: !!(flagsInt & 1 << 7), // Extension Data Present
    flagsInt,
  };

  const counterBuf = authData.slice(pointer, (pointer += 4));
  const counter = counterBuf.readUInt32BE(0);

  let aaguid: Buffer | undefined = undefined;
  let credentialID: Buffer | undefined = undefined;
  let credentialPublicKey: Buffer | undefined = undefined;

  if (flags.at) {
    aaguid = authData.slice(pointer, (pointer += 16));

    const credIDLenBuf = authData.slice(pointer, (pointer += 2));
    const credIDLen = credIDLenBuf.readUInt16BE(0);

    credentialID = authData.slice(pointer, (pointer += credIDLen));

    // Decode the next CBOR item in the buffer, then re-encode it back to a Buffer
    const firstDecoded = decodeCborFirst(authData.slice(pointer));
    const firstEncoded = Buffer.from(cbor.encode(firstDecoded) as ArrayBuffer);
    credentialPublicKey = firstEncoded;
    pointer += firstEncoded.byteLength;
  }

  let authenticatorExtensionResults: AuthenticationExtensionsAuthenticatorOutputs | undefined = undefined;
  let authenticatorExtensionsDataBuffer: Buffer | undefined = undefined;

  if (flags.ed) {
    const firstDecoded = decodeCborFirst(authData.slice(pointer));
    const firstEncoded = Buffer.from(cbor.encode(firstDecoded) as ArrayBuffer);
    authenticatorExtensionsDataBuffer = firstEncoded;
    authenticatorExtensionResults = decodeAuthenticatorExtensions(authenticatorExtensionsDataBuffer);
    pointer += firstEncoded.byteLength;
  }

  // Pointer should be at the end of the authenticator data, otherwise too much data was sent
  if (authData.byteLength > pointer) {
    throw new Error('Leftover bytes detected while parsing authenticator data');
  }

  return {
    rpIdHash,
    flagsBuf,
    flags,
    counter,
    counterBuf,
    aaguid,
    credentialID,
    credentialPublicKey,
    authenticatorExtensionResults,
    authenticatorExtensionsDataBuffer
  };
}

export type ParsedAuthenticatorData = {
  rpIdHash: Buffer;
  flagsBuf: Buffer;
  flags: {
    up: boolean;
    uv: boolean;
    be: boolean;
    bs: boolean;
    at: boolean;
    ed: boolean;
    flagsInt: number;
  };
  counter: number;
  counterBuf: Buffer;
  aaguid?: Buffer;
  credentialID?: Buffer;
  credentialPublicKey?: Buffer;
  authenticatorExtensionResults?: AuthenticationExtensionsAuthenticatorOutputs;
  authenticatorExtensionsDataBuffer?: Buffer;
};
