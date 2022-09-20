import { decodeCborFirst } from '../../helpers/decodeCbor';
import {
  AuthenticationExtensionsDevicePublicKeyOutputs,
  AuthenticationExtensionsDevicePublicKeyOutputsJSON,
  AttestationFormat,
  AttestationStatement,
} from '@simplewebauthn/typescript-types';
import base64url from 'base64url';

/**
 * Convert base64url encoded device public key client extension data to buffer
 *
 * @param devicePubKey Base64url encoded device public key data obtained from
 * client extension results
 */
export function decodeDevicePubKey(
  devicePubKeyJSON: AuthenticationExtensionsDevicePublicKeyOutputsJSON,
): AuthenticationExtensionsDevicePublicKeyOutputs {
  const {
    authenticatorOutput: base64AuthenticatorOutput,
    signature: base64Signature,
  } = devicePubKeyJSON;

  let authenticatorOutput: Buffer | undefined;
  let signature: Buffer | undefined;

  try {
    authenticatorOutput = base64url.toBuffer(base64AuthenticatorOutput);
    if (!authenticatorOutput) {
      throw new Error ('authenticatorOutput is missing');
    }

    signature = base64url.toBuffer(base64Signature);
    if (!signature) {
      throw new Error('signature is missing');
    }
  } catch (err) {
    const _err = err as Error;
    throw new Error(`Error decoding device public key: ${_err.message}`);
  }

  const devicePubKey: AuthenticationExtensionsDevicePublicKeyOutputs = {
    authenticatorOutput,
    signature,
  }
  return devicePubKey;
}

/**
 * Decode device public key authenticator output data CBOR to JSON 
 * @param authenticatorOutput CBOR encoded device public key authenticator
 * output
 * @returns JSON based device public key authenticator data
 */
export function decodeDevicePubKeyAuthenticatorOutput(
  authenticatorOutput: Buffer,
): DevicePublicKeyAuthenticatorOutput {
  let toCBOR: DevicePublicKeyAuthenticatorOutput;
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
  scope: number;
  fmt: AttestationFormat;
  attStmt: AttestationStatement;
  nonce?: Buffer;
};
