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

const devicePubKeyJSON: DevicePublicKeyAuthenticatorOutputJSON = {
  dpk: 'pQECAyYgASFYIO3q0_01dpwj00DdwYMKf_IOc1XynRx1qg3CtqwYLqfTIlggNFHcmZKvlGgltEGUX8nRNOF7c6pf6pWANR58k_XTZRM',
  nonce: '',
  scope: 0,
  aaguid: 'uT_ZYfLmRi-xIoIAIkfeeA',
  fmt: 'none',
  attStmt: {},
}

const differentDevicePubKey: DevicePublicKeyAuthenticatorOutput = {
  dpk: Buffer.from('a5010203262001215820991aabed9de4271a9edead8806f9dc96d6dccd0c476253a5510489ec8379be5b225820a0973cfdedbb79e27fef4ee7481673fb3312504ddca5434cfd23431d6ad29eda', 'hex'),
  nonce: Buffer.from('', 'hex'),
  scope: 0,
  aaguid: Buffer.from('B93FD961F2E6462FB12282002247DE78', 'hex'),
  fmt: 'none',
  attStmt: {},
};

const differentDevicePubKeyJSON: DevicePublicKeyAuthenticatorOutputJSON = {
  dpk: 'pQECAyYgASFYIJkaq-2d5Ccant6tiAb53JbW3M0MR2JTpVEEieyDeb5bIlggoJc8_e27eeJ_707nSBZz-zMSUE3cpUNM_SNDHWrSnto',
  nonce: '',
  scope: 0,
  aaguid: 'uT_ZYfLmRi-xIoIAIkfeeA',
  fmt: 'none',
  attStmt: {},
};

it("should throw when more than two device public key matches", async () => {
  await expect(isRecognizedDevice(devicePubKey, [devicePubKeyJSON, devicePubKeyJSON])).rejects.toThrowError(new Error('It is undetermined whether this is a known device.'));
});

it("should return the unrecognized new device public key", async () => {
  await expect(isRecognizedDevice(devicePubKey, [differentDevicePubKeyJSON, differentDevicePubKeyJSON])).resolves.toMatchObject({
    authenticatorOutput: devicePubKey,
    recognitionResult: 'unrecognized'
  });
});

it("should return one recognized device public key that matches", async () => {
  await expect(isRecognizedDevice(devicePubKey, [devicePubKeyJSON, differentDevicePubKeyJSON])).resolves.toMatchObject({
    authenticatorOutput: devicePubKey,
    recognitionResult: 'recognized'
  });
});

// Needs test data
// it("should return true on equal attestation statement", () => {
//   const responseAttStmt: AttestationStatement = {};
//   const expectedAttStmt: AttestationStatement = {};

//   const result = checkAttStmtBinaryEquality(responseAttStmt, expectedAttStmt);
//   expect(result).toEqual(true);
// });
