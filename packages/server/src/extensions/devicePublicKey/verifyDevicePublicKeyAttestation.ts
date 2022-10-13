import { DevicePublicKeyAuthenticatorOutput } from "./decodeDevicePubKey";

/**
 * https://w3c.github.io/webauthn/#sctn-device-publickey-extension-verification-create
 * 3. Verify that `signature` is a valid signature over the assertion signature
 *    input by the device public key *dpk*. (The signature algorithm is the same
 *    as for the user credential.)
 * @param options 
 * @returns Promise<boolean>
 */
export async function verifyDevicePublicKeyAttestation(
  devicePubKey: DevicePublicKeyAuthenticatorOutput
): Promise<boolean> {
  const { fmt } = devicePubKey;
  if (fmt === 'none') {
    return true;
  } else {
    throw new Error('Attestation verification on a device public key is not implemented yet.');

    // TODO: Implement the attestation verification logic.
    // const prefix = Buffer.from('64657669636520626f756e64206b6579206174746573746174696f6e2073696700ffffffff', 'hex');
    // const authData = Buffer.concat([prefix, aaguid]);
    // const clientDataHash = Buffer.concat([dpk, nonce || Buffer.from('')]);
  }
}
