import { decodeCborFirst } from './decodeCbor';

/**
 * Convert authenticator extension data buffer to a proper object
 *
 * @param extensionData Authenticator Extension Data buffer
 */
export function decodeAuthenticatorExtensions(
  extensionData: Uint8Array,
): AuthenticationExtensionsAuthenticatorOutputs | undefined {
  let toCBOR: AuthenticationExtensionsAuthenticatorOutputs | undefined;
  try {
    toCBOR = decodeCborFirst(extensionData);
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

export type DevicePublicKeyAuthenticatorOutput = {
  dpk?: Uint8Array;
  scp?: Uint8Array;
  sig?: string;
  aaguid?: Uint8Array;
};

// TODO: Need to verify this format
// https://w3c.github.io/webauthn/#sctn-uvm-extension.
export type UVMAuthenticatorOutput = {
  uvm?: Uint8Array[];
};
