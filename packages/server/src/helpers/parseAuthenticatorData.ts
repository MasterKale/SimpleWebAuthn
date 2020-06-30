import cbor from 'cbor';

/**
 * Make sense of the authData buffer contained in an Attestation
 */
export default function parseAuthenticatorData(authData: Buffer): ParsedAuthenticatorData {
  if (authData.byteLength < 37) {
    throw new Error(
      `Authenticator data was ${authData.byteLength} bytes, expected at least 37 bytes`,
    );
  }

  let intBuffer = authData;

  const rpIdHash = intBuffer.slice(0, 32);
  intBuffer = intBuffer.slice(32);

  const flagsBuf = intBuffer.slice(0, 1);
  intBuffer = intBuffer.slice(1);

  const flagsInt = flagsBuf[0];

  const flags = {
    up: !!(flagsInt & 0x01),
    uv: !!(flagsInt & 0x04),
    at: !!(flagsInt & 0x40),
    ed: !!(flagsInt & 0x80),
    flagsInt,
  };

  const counterBuf = intBuffer.slice(0, 4);
  intBuffer = intBuffer.slice(4);

  const counter = counterBuf.readUInt32BE(0);

  let aaguid: Buffer | undefined = undefined;
  let credentialID: Buffer | undefined = undefined;
  let credentialPublicKey: Buffer | undefined = undefined;

  if (flags.at) {
    aaguid = intBuffer.slice(0, 16);
    intBuffer = intBuffer.slice(16);

    const credIDLenBuf = intBuffer.slice(0, 2);
    intBuffer = intBuffer.slice(2);

    const credIDLen = credIDLenBuf.readUInt16BE(0);

    credentialID = intBuffer.slice(0, credIDLen);
    intBuffer = intBuffer.slice(credIDLen);

    // Decode the next CBOR item in the buffer, then re-encode it back to a Buffer
    const firstDecoded = cbor.decodeFirstSync(intBuffer);
    const firstEncoded = cbor.encode(firstDecoded);
    credentialPublicKey = firstEncoded;
    intBuffer = intBuffer.slice(firstEncoded.byteLength);
  }

  let extensionsDataBuffer: Buffer | undefined = undefined;
  if (flags.ed) {
    const firstDecoded = cbor.decodeFirstSync(intBuffer);
    const firstEncoded = cbor.encode(firstDecoded);
    extensionsDataBuffer = firstEncoded;
    intBuffer = intBuffer.slice(firstEncoded.byteLength);
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
    extensionsDataBuffer,
  };
}

export type ParsedAuthenticatorData = {
  rpIdHash: Buffer;
  flagsBuf: Buffer;
  flags: {
    up: boolean;
    uv: boolean;
    at: boolean;
    ed: boolean;
    flagsInt: number;
  };
  counter: number;
  counterBuf: Buffer;
  aaguid?: Buffer;
  credentialID?: Buffer;
  credentialPublicKey?: Buffer;
  extensionsDataBuffer?: Buffer;
};
