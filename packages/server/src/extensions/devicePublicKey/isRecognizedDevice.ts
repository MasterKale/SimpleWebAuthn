import { DevicePublicKeyAuthenticatorOutput } from "../../helpers/decodeAuthenticatorExtensions";
import { verifyDevicePublicKeyAttestation } from "./verifyDevicePublicKeyAttestation";

/**
 * 
 * @param responseDevicePublicKey 
 * @param knownDevicePublicKeys
 * @returns DevicePublicKeyAuthenticatorOutput | undefined
 */
export async function isRecognizedDevice(
  responseDevicePublicKey: DevicePublicKeyAuthenticatorOutput,
  userDevicePublicKeys?: DevicePublicKeyAuthenticatorOutput[]
): Promise<DevicePublicKeyAuthenticatorOutput | undefined> {
  if (userDevicePublicKeys && userDevicePublicKeys.length > 0) {
    // If the Relying Party's user account mapped to the credential.id in play
    // (i.e., for the user being authenticated) holds aaguid, dpk and scope
    // values corresponding to the extracted attObjForDevicePublicKey fields,
    // then perform binary equality checks between the corresponding stored
    // values and the extracted field values. The Relying Party MAY have more
    // than one set of {aaguid, dpk, scope} values mapped to the user account
    // and credential.id pair and each set MUST be checked.
    const matchedDPKs = userDevicePublicKeys.filter(userDPK => {
      if (!responseDevicePublicKey.aaguid.equals(userDPK.aaguid)) {
        return false;
      }
      if (!responseDevicePublicKey.dpk.equals(userDPK.dpk)) {
        return false;
      }
      if (!responseDevicePublicKey.scope.equals(userDPK.scope)) {
        return false;
      }
      return true;
    });

    // more than one match
    if (matchedDPKs.length > 1) {
      throw new Error('It is undetermined whether this is a known device.');
    }

    // exactly one match
    if (matchedDPKs.length === 1) {
      // This is likely a known device. 

      // If fmt’s value is "none" then there
      // is no attestation signature to verify and this is a known device public
      // key with a valid signature and thus a known device. Terminate these
      // verification steps.
      if (!responseDevicePublicKey.fmt || responseDevicePublicKey.fmt === 'none') {
        return;
      } else {
        // Perform a binary equality check of `attStmt`.
        // TODO: if equality check succeeds, 
        if (!equalityCheck()) {
          // This authenticator is not generating a fresh per-response random nonce.
          return;
        } else {
          // Otherwise, verify attestation
          const isValidDPKAttestation = await verifyDevicePublicKeyAttestation(responseDevicePublicKey);
          if (!isValidDPKAttestation) {
            throw new Error('Device Public Key attestation is invalid.');
          }
        }
        // This is a valid and a known device.
        return;
      }
    }

    // zero matches
    if (matchedDPKs.length === 0) {
      // This is possibly a new device.

      const index = userDevicePublicKeys.findIndex(userDPK => {
        return responseDevicePublicKey.dpk.equals(userDPK.dpk)
      });
      if (index === -1) {
        // If `attObjForDevicePublicKey.dpk` did not match any of the Relying
        // Party's stored dpk values for this user account and `credential.id`
        // pair then:
        const isValidDPKAttestation = await verifyDevicePublicKeyAttestation(responseDevicePublicKey);
        if (!isValidDPKAttestation) {
          throw new Error('Device public key attestation is invalid.');
        }
        return responseDevicePublicKey;
      } else {
        // Otherwise there is some form of error: we recieved a known dpk
        // value, but one or more of the accompanying aaguid, scope values
        // did not match what the Relying Party has stored along with that
        // dpk value. Terminate these verification steps.
        throw new Error('It is undetermined whether this is a known device.');
      }
    }
  } else {
    // Otherwise, the Relying Party does not have `attObjForDevicePublicKey`
    // fields presently mapped to this user account and credential.id pair:
    const isValidDPKAttestation = await verifyDevicePublicKeyAttestation(responseDevicePublicKey);
    if (!isValidDPKAttestation) {
      throw new Error('Device Public Key attestation is invalid.');
    }
    return responseDevicePublicKey;
  }
  return;
}