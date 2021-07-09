import cbor from 'cbor';
import { decodeCborFirst } from './decodeCbor';

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

  const flags = {
    up: !!(flagsInt & 0x01),
    uv: !!(flagsInt & 0x04),
    at: !!(flagsInt & 0x40),
    ed: !!(flagsInt & 0x80),
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
    authData = authData.slice((pointer += firstEncoded.byteLength));
  }

  let extensionsDataBuffer: Buffer | undefined = undefined;
  if (flags.ed) {
    const firstDecoded = decodeCborFirst(authData);
    const firstEncoded = Buffer.from(cbor.encode(firstDecoded) as ArrayBuffer);
    extensionsDataBuffer = firstEncoded;
    authData = authData.slice((pointer += firstEncoded.byteLength));
  }

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
