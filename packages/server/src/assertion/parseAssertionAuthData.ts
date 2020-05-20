import { ParsedAssertionAuthData } from "@libTypes";

/**
 * Make sense of the authData buffer contained in an Assertion
 */
export default function parseAssertionAuthData(authData: Buffer): ParsedAssertionAuthData {
  let intBuffer = authData;

  const rpIdHash = intBuffer.slice(0, 32);
  intBuffer = intBuffer.slice(32);

  const flagsBuf = intBuffer.slice(0, 1);
  intBuffer = intBuffer.slice(1);

  const flags = flagsBuf[0];
  const counterBuf = intBuffer.slice(0, 4);
  intBuffer = intBuffer.slice(4);

  const counter = counterBuf.readUInt32BE(0);

  return {
    rpIdHash,
    flagsBuf,
    flags,
    counter,
    counterBuf,
  };
}
