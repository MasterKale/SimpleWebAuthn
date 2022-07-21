import cbor from 'cbor';

/**
 * Convert an extension data buffer to a proper object
 *
 * @param extensionDataBuffer Extension Data buffer
 */
export default function decodeExtensionDataBuffer(extensionDataBuffer: Buffer): AuthenticationExtensionsAuthenticatorOutputs {
  const toCBOR: AuthenticationExtensionsAuthenticatorOutputs = cbor.decodeAllSync(extensionDataBuffer)[0];
  return toCBOR;
}

export type AuthenticationExtensionsAuthenticatorOutputs = {
  devicePublicKey?: DevicePublicKeyJSON;
  uvm?: UvmJSON;
}

export type DevicePublicKeyJSON = {
  dpk?: Buffer;
  scp?: Buffer;
  sig?: string;
  aaguid?: Buffer;
}

// TODO: Need to verify this format
// https://w3c.github.io/webauthn/#sctn-uvm-extension.
export type UvmJSON = {
  uvm?: Buffer[]
}
