import { AttestationStatement } from "../../helpers/decodeAttestationObject";
import { DevicePublicKeyAuthenticatorOutput } from './decodeDevicePubKey';
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
      if (responseDevicePublicKey.scope !== userDPK.scope) {
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
          throw new Error('DevicePublicKey attestation could not be verified');
        }
        // When `fmt` is `none` or the device public key attestation is valid, store the DPK.
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
    if (responseDevicePublicKey.fmt !== 'none') {
      // Perform a binary equality check of `attStmt`.
      const recognizedDPKAttStmt = matchedDPKs[0].attStmt;
      try {
        // Unless thrown, this always returns `true`.
        checkAttStmtBinaryEquality(responseDevicePublicKey.attStmt, recognizedDPKAttStmt);
      } catch (err) {
        // const _err = err as Error;
        // How do we message the error cause?
        // throw new Error(`DevicePublicKey attStmt's were not equal: ${_err.message}`);
        // Otherwise, verify attestation
        const isValidDPKAttestation = await verifyDevicePublicKeyAttestation(responseDevicePublicKey);
        if (!isValidDPKAttestation) {
          throw new Error('DevicePublicKey attestation could not be verified.');
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
      throw new Error('DevicePublicKey attestation could not be verified');
    }
    // When `fmt` is `none` or the device public key attestation is valid, store the DPK.
    return responseDevicePublicKey;
  }
}

export function checkAttStmtBinaryEquality(
  responseDPKAttStmt?: AttestationStatement,
  recognizedDPKAttStmt?: AttestationStatement
): boolean {
  // `attStmt` in device public key is not optional, but for an interim solution:
  if (!responseDPKAttStmt || ! recognizedDPKAttStmt) {
    throw new Error('attStmt in a DevicePublicKey is missing.');
  }

  if (!responseDPKAttStmt.sig || !recognizedDPKAttStmt.sig || !responseDPKAttStmt.sig.equals(recognizedDPKAttStmt.sig)) {
    throw new Error("Response DPK sig and recognized DPK sig did not match.")
  }
  if (!responseDPKAttStmt.x5c || !recognizedDPKAttStmt.x5c) {
    throw new Error("Response DPK x5c and recognized DPK x5c did not match.")
  }
  if (responseDPKAttStmt.x5c.length !== recognizedDPKAttStmt.x5c.length) {
    throw new Error("Response DPK x5c length and recognized DPK x5c length did not match.")
  }
  for (let i = 0; i < responseDPKAttStmt.x5c.length; i++) {
    if (!responseDPKAttStmt.x5c[i].equals(recognizedDPKAttStmt.x5c[i])) {
      throw new Error("Response DPK x5c length and recognized DPK x5c length did not match.")
    }
  }
  if (!responseDPKAttStmt.response || !recognizedDPKAttStmt.response || !responseDPKAttStmt.response.equals(recognizedDPKAttStmt.response)) {
    throw new Error("Response DPK response and recognized DPK response did not match.")
  }
  if (responseDPKAttStmt.alg !== recognizedDPKAttStmt.alg) {
    throw new Error("Response DPK alg and recognized DPK alg did not match.")
  }
  if (responseDPKAttStmt.ver !== recognizedDPKAttStmt.ver) {
    throw new Error("Response DPK ver and recognized DPK ver did not match.")
  }
  if (!responseDPKAttStmt.certInfo || !recognizedDPKAttStmt.certInfo || !responseDPKAttStmt.certInfo.equals(recognizedDPKAttStmt.certInfo)) {
    throw new Error("Response DPK certInfo and recognized DPK certInfo did not match.")
  }
  if (!responseDPKAttStmt.pubArea || !recognizedDPKAttStmt.pubArea || !responseDPKAttStmt.pubArea.equals(recognizedDPKAttStmt.pubArea)) {
    throw new Error("Response DPK pubArea and recognized DPK pubArea did not match.")
  }
  return true;
}
