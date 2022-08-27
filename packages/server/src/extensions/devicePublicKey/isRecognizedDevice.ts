import { AttestationStatement } from "helpers";
import { DevicePublicKeyAuthenticatorOutput } from "../../helpers/decodeAuthenticatorExtensions";
import { verifyDevicePublicKeyAttestation } from "./verifyDevicePublicKeyAttestation";

/**
 * Checks if the device public key matches one of stored DPKs as per described
 * at 10.2.2.3.2 of the spec. If it's a known device, returns undefined. If it's
 * a new but valid device, returns the device public key so that the RP can
 * store it. Throws when it's an invalid device or any unexpected issue occurs.
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

    // Everything else is exactly one match
    // This is likely a known device. 

    // If fmt’s value is "none" then there
    // is no attestation signature to verify and this is a known device public
    // key with a valid signature and thus a known device. Terminate these
    // verification steps.
    if (responseDevicePublicKey.fmt && responseDevicePublicKey.fmt !== 'none') {
      // Perform a binary equality check of `attStmt`.
      const knownAttStmt = matchedDPKs[0].attStmt;
      if (!checkAttStmtBinaryEquality(responseDevicePublicKey.attStmt, knownAttStmt)) {
        // Otherwise, verify attestation
        const isValidDPKAttestation = await verifyDevicePublicKeyAttestation(responseDevicePublicKey);
        if (!isValidDPKAttestation) {
          throw new Error('Device Public Key attestation is invalid.');
        }
      }
    }
    // This is a valid and a known device.
    return;

  } else {
    // Otherwise, the Relying Party does not have `attObjForDevicePublicKey`
    // fields presently mapped to this user account and credential.id pair:
    const isValidDPKAttestation = await verifyDevicePublicKeyAttestation(responseDevicePublicKey);
    if (!isValidDPKAttestation) {
      throw new Error('Device Public Key attestation is invalid.');
    }
    return responseDevicePublicKey;
  }
}

export function checkAttStmtBinaryEquality(
  responseAttStmt?: AttestationStatement,
  knownAttStmt?: AttestationStatement
): boolean {
  // `attStmt` in device public key is not optional, but for an interim solution:
  if (!responseAttStmt || ! knownAttStmt) {
    return false;
  }

  if (!responseAttStmt.sig || !knownAttStmt.sig || !responseAttStmt.sig.equals(knownAttStmt.sig)) {
    return false;
  }
  if (!responseAttStmt.x5c || !knownAttStmt.x5c) {
    return false;
  }
  if (responseAttStmt.x5c.length !== knownAttStmt.x5c.length) {
    return false;
  }
  for (let i = 0; i < responseAttStmt.x5c.length; i++) {
    if (!responseAttStmt.x5c[i].equals(knownAttStmt.x5c[i])) {
      return false;
    }
  }
  if (!responseAttStmt.response || !knownAttStmt.response || !responseAttStmt.response.equals(knownAttStmt.response)) {
    return false;
  }
  if (responseAttStmt.alg !== knownAttStmt.alg) {
    return false;
  }
  if (responseAttStmt.ver !== knownAttStmt.ver) {
    return false;
  }
  if (!responseAttStmt.certInfo || !knownAttStmt.certInfo || !responseAttStmt.certInfo.equals(knownAttStmt.certInfo)) {
    return false;
  }
  if (!responseAttStmt.pubArea || !knownAttStmt.pubArea || !responseAttStmt.pubArea.equals(knownAttStmt.pubArea)) {
    return false;
  }
  return true;
}
