import { checkAttStmtBinaryEquality, isRecognizedDevice } from './isRecognizedDevice';
import { AttestationStatement } from "../../helpers/decodeAttestationObject";
import { DevicePublicKeyAuthenticatorOutput } from '../../helpers/decodeAuthenticatorExtensions';

const devicePubKey: DevicePublicKeyAuthenticatorOutput = {
  "dpk": Buffer.from('A5010203262001215820EDEAD3FD35769C23D340DDC1830A7FF20E7355F29D1C75AA0DC2B6AC182EA7D32258203451DC9992AF946825B441945FC9D134E17B73AA5FEA9580351E7C93F5D36513', 'hex'),
  "sig": Buffer.from('3045022100BC6DD9AF5E47BB3AB82731299EAE82A779189E4E416E3A0E37A3BA64C38F991202205671EFAC0E8CD6DE1D3640CE7E4E89D3A97E0517B603D8AC28F23E4E1F74E639', 'hex'),
  "nonce": Buffer.from('', 'hex'),
  "scope": Buffer.from('00', 'hex'),
  "aaguid": Buffer.from('B93FD961F2E6462FB12282002247DE78', 'hex'),
}

const sameDevicePubKey = devicePubKey;
const differentDevicePubKey: DevicePublicKeyAuthenticatorOutput = {
  "dpk": Buffer.from('A5010203262001215820991AABED9DE4271A9EDEAD8806F9DC96D6DCCD0C476253A5510489EC8379BE5B225820A0973CFDEDBB79E27FEF4EE7481673FB3312504DDCA5434CFD23431D6AD29EDA', 'hex'),
  "sig": Buffer.from('3045022049526CD28AEF6B4E621A7D5936D2B504952FC0AE2313A4F0357AAFFFAEA964740221009D513ACAEFB0B32C765AAE6FEBA8C294685EFF63FF1CBF11ECF2107AF4FEB8F8', 'hex'),
  "nonce": Buffer.from('', 'hex'),
  "scope": Buffer.from('00', 'hex'),
  "aaguid": Buffer.from('B93FD961F2E6462FB12282002247DE78', 'hex'),
};

it("should throw when more than two device public key matches", async () => {
  expect(isRecognizedDevice(devicePubKey, [sameDevicePubKey, sameDevicePubKey])).rejects.toThrowError(new Error('It is undetermined whether this is a known device.'));
});

it("should return the new device public key when no device public key matches", async () => {
  expect(isRecognizedDevice(devicePubKey, [differentDevicePubKey, differentDevicePubKey])).resolves.toMatchObject(sameDevicePubKey);
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
