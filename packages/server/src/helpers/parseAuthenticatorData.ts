import {
  AuthenticationExtensionsAuthenticatorOutputs,
  decodeAuthenticatorExtensions,
} from './decodeAuthenticatorExtensions.ts';
import { isoCBOR, isoUint8Array } from './iso/index.ts';
import { COSEPublicKey } from './cose.ts';

/**
 * Make sense of the authData buffer contained in an Attestation
 */
export function parseAuthenticatorData(
  authData: Uint8Array,
): ParsedAuthenticatorData {
  if (authData.byteLength < 37) {
    throw new Error(
      `Authenticator data was ${authData.byteLength} bytes, expected at least 37 bytes`,
    );
  }

  let pointer = 0;
  const dataView = isoUint8Array.toDataView(authData);

  const rpIdHash = authData.slice(pointer, pointer += 32);

  const flagsBuf = authData.slice(pointer, pointer += 1);
  const flagsInt = flagsBuf[0];

  // Bit positions can be referenced here:
  // https://www.w3.org/TR/webauthn-2/#flags
  const flags = {
    up: !!(flagsInt & (1 << 0)), // User Presence
    uv: !!(flagsInt & (1 << 2)), // User Verified
    be: !!(flagsInt & (1 << 3)), // Backup Eligibility
    bs: !!(flagsInt & (1 << 4)), // Backup State
    at: !!(flagsInt & (1 << 6)), // Attested Credential Data Present
    ed: !!(flagsInt & (1 << 7)), // Extension Data Present
    flagsInt,
  };

  const counterBuf = authData.slice(pointer, pointer + 4);
  const counter = dataView.getUint32(pointer, false);
  pointer += 4;

  let aaguid: Uint8Array | undefined = undefined;
  let credentialID: Uint8Array | undefined = undefined;
  let credentialPublicKey: Uint8Array | undefined = undefined;

  if (flags.at) {
    aaguid = authData.slice(pointer, pointer += 16);

    const credIDLen = dataView.getUint16(pointer);
    pointer += 2;

    credentialID = authData.slice(pointer, pointer += credIDLen);

    /**
     * Firefox 117 incorrectly CBOR-encodes authData when EdDSA (-8) is used for the public key.
     * A CBOR "Map of 3 items" (0xa3) should be "Map of 4 items" (0xa4), and if we manually adjust
     * the single byte there's a good chance the authData can be correctly parsed.
     */
    // Bytes decode to `{ 1: "OKP", 3: -8, -1: "Ed25519" }` (it's missing key -2 a.k.a. COSEKEYS.x)
    const badEdDSACBOR = isoUint8Array.fromHex('a301634f4b500327206745643235353139');
    const bytesAtCurrentPosition = authData.slice(pointer, pointer + badEdDSACBOR.byteLength);
    if (isoUint8Array.areEqual(badEdDSACBOR, bytesAtCurrentPosition)) {
      // Change the bad CBOR 0xa3 to 0xa4 so that the credential public key can be recognized
      authData[pointer] = 0xa4;
    }

    // Decode the next CBOR item in the buffer, then re-encode it back to a Buffer
    const firstDecoded = isoCBOR.decodeFirst<COSEPublicKey>(
      authData.slice(pointer),
    );
    const firstEncoded = Uint8Array.from(isoCBOR.encode(firstDecoded));

    credentialPublicKey = firstEncoded;
    pointer += firstEncoded.byteLength;
  }

  let extensionsData: AuthenticationExtensionsAuthenticatorOutputs | undefined = undefined;
  let extensionsDataBuffer: Uint8Array | undefined = undefined;

  if (flags.ed) {
    const firstDecoded = isoCBOR.decodeFirst(authData.slice(pointer));
    extensionsDataBuffer = Uint8Array.from(isoCBOR.encode(firstDecoded));
    extensionsData = decodeAuthenticatorExtensions(extensionsDataBuffer);
    pointer += extensionsDataBuffer.byteLength;
  }

  // Pointer should be at the end of the authenticator data, otherwise too much data was sent
  if (authData.byteLength > pointer) {
    throw new Error('Leftover bytes detected while parsing authenticator data');
  }

  return _parseAuthenticatorDataInternals.stubThis({
    rpIdHash,
    flagsBuf,
    flags,
    counter,
    counterBuf,
    aaguid,
    credentialID,
    credentialPublicKey,
    extensionsData,
    extensionsDataBuffer,
  });
}

export type ParsedAuthenticatorData = {
  rpIdHash: Uint8Array;
  flagsBuf: Uint8Array;
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
  counterBuf: Uint8Array;
  aaguid?: Uint8Array;
  credentialID?: Uint8Array;
  credentialPublicKey?: Uint8Array;
  extensionsData?: AuthenticationExtensionsAuthenticatorOutputs;
  extensionsDataBuffer?: Uint8Array;
};

// Make it possible to stub the return value during testing
export const _parseAuthenticatorDataInternals = {
  stubThis: (value: ParsedAuthenticatorData) => value,
};
