import { isRecognizedDevice } from './isRecognizedDevice';
import {
  DevicePublicKeyAuthenticatorOutput,
  DevicePublicKeyAuthenticatorOutputJSON,
} from './decodeDevicePubKey';

const devicePubKey: DevicePublicKeyAuthenticatorOutput = {
  dpk: Buffer.from('A5010203262001215820EDEAD3FD35769C23D340DDC1830A7FF20E7355F29D1C75AA0DC2B6AC182EA7D32258203451DC9992AF946825B441945FC9D134E17B73AA5FEA9580351E7C93F5D36513', 'hex'),
  nonce: Buffer.from('', 'hex'),
  scope: 0,
  aaguid: Buffer.from('B93FD961F2E6462FB12282002247DE78', 'hex'),
  fmt: 'none',
  attStmt: {},
}

const sameDevicePubKey: DevicePublicKeyAuthenticatorOutputJSON = {
  dpk: 'pQECAyYgASFYIO3q0_01dpwj00DdwYMKf_IOc1XynRx1qg3CtqwYLqfTIlggNFHcmZKvlGgltEGUX8nRNOF7c6pf6pWANR58k_XTZRM',
  nonce: '',
  scope: 0,
  aaguid: 'uT_ZYfLmRi-xIoIAIkfeeA',
  fmt: 'none',
  attStmt: {},
}

const differentDevicePubKey: DevicePublicKeyAuthenticatorOutputJSON = {
  dpk: 'pQECAyYgASFYIJkaq-2d5Ccant6tiAb53JbW3M0MR2JTpVEEieyDeb5bIlggoJc8_e27eeJ_707nSBZz-zMSUE3cpUNM_SNDHWrSnto',
  nonce: '',
  scope: 0,
  aaguid: 'uT_ZYfLmRi-xIoIAIkfeeA',
  fmt: 'none',
  attStmt: {},
};

it("should throw when more than two device public key matches", async () => {
  expect(isRecognizedDevice(devicePubKey, [sameDevicePubKey, sameDevicePubKey])).rejects.toThrowError(new Error('It is undetermined whether this is a known device.'));
});

it("should return the new device public key when no device public key matches", async () => {
  expect(isRecognizedDevice(devicePubKey, [differentDevicePubKey, differentDevicePubKey])).resolves.toMatchObject(devicePubKey);
});

it("should return undefined when one device public key matches", async () => {
  expect(isRecognizedDevice(devicePubKey, [sameDevicePubKey, differentDevicePubKey])).resolves.toBeUndefined();
});

// Needs test data
// it("should return true on equal attestation statement", () => {
//   const responseAttStmt: AttestationStatement = {};
//   const expectedAttStmt: AttestationStatement = {};

//   const result = checkAttStmtBinaryEquality(responseAttStmt, expectedAttStmt);
//   expect(result).toEqual(true);
// });
