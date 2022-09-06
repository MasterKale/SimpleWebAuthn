import { decodeCborFirst } from '../../helpers/decodeCbor';
import { Base64URLString, AuthenticationExtensionsDevicePublicKeyOutputs } from '@simplewebauthn/typescript-types';
import { AttestationFormat, AttestationStatement } from '../../helpers/decodeAttestationObject';
import base64url from 'base64url';

/**
 * Convert device public key client extension data buffer to a proper object
 *
 * @param devicePubKey Client Extension's device public key data buffer
 */
export function decodeDevicePubKey(
  devicePubKey: Base64URLString,
): AuthenticationExtensionsDevicePublicKeyOutputs | undefined {
  let toCBOR: AuthenticationExtensionsDevicePublicKeyOutputs | undefined;
  try {
    const base64DevicePubKey = base64url.toBuffer(devicePubKey);
    toCBOR = decodeCborFirst(base64DevicePubKey);
  } catch (err) {
    const _err = err as Error;
    throw new Error(`Error decoding device public key: ${_err.message}`);
  }
  return toCBOR;
}

export function decodeDevicePubKeyAuthenticatorOutput(
  authenticatorOutput: Buffer,
): DevicePublicKeyAuthenticatorOutput | undefined {
  let toCBOR: DevicePublicKeyAuthenticatorOutput | undefined;
  try {
    toCBOR = decodeCborFirst(authenticatorOutput);
  } catch (err) {
    const _err = err as Error;
    throw new Error(`Error decoding device public key authenticator output: ${_err.message}`);
  }
  return toCBOR;
}

export type DevicePublicKeyAuthenticatorOutput = {
  aaguid: Buffer;
  dpk: Buffer;
  scope: Buffer;
  nonce?: Buffer;
  fmt?: AttestationFormat;
  attStmt?: AttestationStatement;
};
