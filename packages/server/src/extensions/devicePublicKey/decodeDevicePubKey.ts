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
export function deserializeDevicePubKeyAuthenticatorOutput(
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

export function encodeDevicePubKeyAuthenticatorOutput(
  devicePubKey: DevicePublicKeyAuthenticatorOutput
): DevicePublicKeyAuthenticatorOutputJSON {
  const base64Aaguid = base64url.encode(devicePubKey.aaguid);
  const base64Dpk = base64url.encode(devicePubKey.dpk);
  const base64Nonce = devicePubKey.nonce ? base64url.encode(devicePubKey.nonce) : undefined;

  const encodedDevicePubKey: DevicePublicKeyAuthenticatorOutputJSON = {
    aaguid: base64Aaguid,
    dpk: base64Dpk,
    scope: devicePubKey.scope,
    nonce: base64Nonce,
    fmt: devicePubKey.fmt || 'none',
  };

  encodedDevicePubKey.attStmt = {};

  if (devicePubKey.fmt !== 'none' && devicePubKey.attStmt) {
    const { attStmt } = devicePubKey;
    encodedDevicePubKey.attStmt.sig = attStmt.sig ? base64url.encode(attStmt.sig) : '';
    encodedDevicePubKey.attStmt.x5c = [];
    if (attStmt.x5c && attStmt.x5c.length > 0) {
      for (const x of attStmt.x5c) {
        encodedDevicePubKey.attStmt.x5c.push(base64url.encode(x));
      }
    }
    encodedDevicePubKey.attStmt.response = attStmt.response ? base64url.encode(attStmt.response) : '';
    encodedDevicePubKey.attStmt.certInfo = attStmt.certInfo ? base64url.encode(attStmt.certInfo) : '';
    encodedDevicePubKey.attStmt.pubArea = attStmt.pubArea ? base64url.encode(attStmt.pubArea) : '';
    encodedDevicePubKey.attStmt.alg = attStmt.alg;
    encodedDevicePubKey.attStmt.ver = attStmt.ver;
  }

  return encodedDevicePubKey;
}

export function decodeDevicePubKeyAuthenticatorOutput(
  encodedDevicePubKey: DevicePublicKeyAuthenticatorOutputJSON
): DevicePublicKeyAuthenticatorOutputExtended {
  const aaguid = base64url.toBuffer(encodedDevicePubKey.aaguid);
  const dpk = base64url.toBuffer(encodedDevicePubKey.dpk);
  const scope = encodedDevicePubKey.scope;
  const nonce = encodedDevicePubKey.nonce ? base64url.toBuffer(encodedDevicePubKey.nonce) : Buffer.from('', 'hex');
  const fmt = encodedDevicePubKey.fmt ? encodedDevicePubKey.fmt : 'none';

  const decodedDevicePubKey: DevicePublicKeyAuthenticatorOutputExtended = {
    ...encodedDevicePubKey,
    aaguid,
    dpk,
    scope,
    nonce,
    fmt,
    attStmt: {}
  }

  if (encodedDevicePubKey.fmt !== 'none' && encodedDevicePubKey.attStmt) {
    const { attStmt: encodedAttStmt } = encodedDevicePubKey;
    decodedDevicePubKey.attStmt.sig = encodedAttStmt.sig ? base64url.toBuffer(encodedAttStmt.sig) : undefined;
    decodedDevicePubKey.attStmt.x5c = [];
    if (encodedAttStmt.x5c && encodedAttStmt.x5c.length > 0) {
      for (const x of encodedAttStmt.x5c) {
        decodedDevicePubKey.attStmt.x5c.push(base64url.toBuffer(x));
      }
    }
    decodedDevicePubKey.attStmt.response = encodedAttStmt.response ? base64url.toBuffer(encodedAttStmt.response) : undefined;
    decodedDevicePubKey.attStmt.certInfo = encodedAttStmt.certInfo ? base64url.toBuffer(encodedAttStmt.certInfo) : undefined;
    decodedDevicePubKey.attStmt.pubArea = encodedAttStmt.pubArea ? base64url.toBuffer(encodedAttStmt.pubArea) : undefined;
    decodedDevicePubKey.attStmt.alg = encodedAttStmt.alg;
    decodedDevicePubKey.attStmt.ver = encodedAttStmt.ver;
  }
  return decodedDevicePubKey;
}
export type DevicePublicKeyAuthenticatorOutput = {
  aaguid: Buffer;
  dpk: Buffer;
  scope: number;
  fmt: AttestationFormat;
  attStmt: AttestationStatement;
  nonce?: Buffer;
};

export type DevicePublicKeyAuthenticatorOutputExtended =
  DevicePublicKeyAuthenticatorOutput | {[key: string]: any}

export type DevicePublicKeyAuthenticatorOutputJSON = {
  [key: string]: any;
  aaguid: string;
  dpk: string;
  scope: number;
  nonce?: string;
  fmt?: AttestationFormat;
  attStmt?: {
    sig?: string;
    x5c?: string[];
    response?: string;
    alg?: number;
    ver?: string;
    certInfo?: string;
    pubArea?: string;
  };
}
