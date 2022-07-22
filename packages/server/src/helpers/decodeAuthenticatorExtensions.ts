import cbor from 'cbor';

/**
 * Convert authenticator extension data buffer to a proper object
 *
 * @param extensionData Authenticator Extension Data buffer
 */
export default function decodeAuthenticatorExtensionData(
  extensionData: Buffer
): AuthenticationExtensionsAuthenticatorOutputs | undefined {
  let toCBOR: AuthenticationExtensionsAuthenticatorOutputs | undefined;
  try {
    toCBOR = cbor.decodeAllSync(extensionData)[0];
  } catch (e) {
    console.error(e);
    toCBOR = undefined;
  }
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
