import cbor from 'cbor';
import { DevicePublicKeyAuthenticatorOutput } from '../extensions/devicePublicKey/decodeDevicePubKey';

/**
 * Convert authenticator extension data buffer to a proper object
 *
 * @param extensionData Authenticator Extension Data buffer
 */
export function decodeAuthenticatorExtensions(
  extensionData: Buffer,
): AuthenticationExtensionsAuthenticatorOutputs | undefined {
  let toCBOR: AuthenticationExtensionsAuthenticatorOutputs | undefined;
  try {
    toCBOR = cbor.decodeAllSync(extensionData)[0];
  } catch (err) {
    const _err = err as Error;
    throw new Error(`Error decoding authenticator extensions: ${_err.message}`);
  }
  return toCBOR;
}

export type AuthenticationExtensionsAuthenticatorOutputs = {
  devicePubKey?: DevicePublicKeyAuthenticatorOutput;
  uvm?: UVMAuthenticatorOutput;
};

// TODO: Need to verify this format
// https://w3c.github.io/webauthn/#sctn-uvm-extension.
export type UVMAuthenticatorOutput = {
  uvm?: Buffer[];
};
