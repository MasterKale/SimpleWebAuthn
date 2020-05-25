import { ParsedAuthenticatorData } from '@webauthntine/typescript-types';

/**
 * Make sense of the authData buffer contained in an Attestation
 */
export default function parseAuthenticatorData(authData: Buffer): ParsedAuthenticatorData {
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
  let COSEPublicKey: Buffer | undefined = undefined;

  if (flags.at) {
    aaguid = intBuffer.slice(0, 16);
    intBuffer = intBuffer.slice(16);

    const credIDLenBuf = intBuffer.slice(0, 2);
    intBuffer = intBuffer.slice(2);

    const credIDLen = credIDLenBuf.readUInt16BE(0);

    credentialID = intBuffer.slice(0, credIDLen);
    intBuffer = intBuffer.slice(credIDLen);

    COSEPublicKey = intBuffer;
  }

  return {
    rpIdHash,
    flagsBuf,
    flags,
    counter,
    counterBuf,
    aaguid,
    credentialID,
    COSEPublicKey,
  };
}
