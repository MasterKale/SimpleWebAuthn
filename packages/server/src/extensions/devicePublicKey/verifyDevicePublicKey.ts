import { DevicePublicKeyAuthenticatorOutput } from "../../helpers/decodeAuthenticatorExtensions";

/**
 * https://pr-preview.s3.amazonaws.com/w3c/webauthn/pull/1663.html#sctn-device-publickey-extension-verification-get
 * 4. If the Relying Party's user account mapped to the *credential*.id in play
 *    (i.e., for the user being authenticated) holds `aaguid`, `dpk`, `scope`,
 *    `fmt`, and `attStmt` values corresponding to the extracted
 *    *attObjForDevicePublicKey* fields, then perform binary equality checks
 *    between the corresponding stored values and the extracted field values.
 * @param devicePubKey 
 * @param expectedDPK 
 * @returns boolean
 */
export function verifyDevicePublicKey(
  devicePubKey: DevicePublicKeyAuthenticatorOutput,
  expectedDPK: DevicePublicKeyAuthenticatorOutput
): boolean {
  if (!devicePubKey.aaguid.equals(expectedDPK.aaguid)) {
    return false;
  }
  if (!devicePubKey.dpk.equals(expectedDPK.dpk)) {
    return false;
  }
  if (!devicePubKey.scope.equals(expectedDPK.scope)) {
    return false;
  }
  if (devicePubKey.fmt !== expectedDPK.fmt) {
    return false;
  }
  if (devicePubKey.attStmt && expectedDPK.attStmt) {
    const { attStmt } = devicePubKey;
    const expectedAttStmt = expectedDPK.attStmt;

    if (!attStmt.sig || !expectedAttStmt.sig || !attStmt.sig.equals(expectedAttStmt.sig)) {
      return false;
    }
    if (!attStmt.x5c || !expectedAttStmt.x5c) {
      return false;
    }
    if (attStmt.x5c.length !== expectedAttStmt.x5c.length) {
      return false;
    }
    for (let i = 0; i < attStmt.x5c.length; i++) {
      if (!attStmt.x5c[i].equals(expectedAttStmt.x5c[i])) {
        return false;
      }
    }
    if (!attStmt.response || !expectedAttStmt.response || !attStmt.response.equals(expectedAttStmt.response)) {
      return false;
    }
    if (attStmt.alg !== expectedAttStmt.alg) {
      return false;
    }
    if (attStmt.ver !== expectedAttStmt.ver) {
      return false;
    }
    if (!attStmt.certInfo || !expectedAttStmt.certInfo || !attStmt.certInfo.equals(expectedAttStmt.certInfo)) {
      return false;
    }
    if (!attStmt.pubArea || !expectedAttStmt.pubArea || !attStmt.pubArea.equals(expectedAttStmt.pubArea)) {
      return false;
    }
  } else {
    // `attStmt` is required field, though at the moment, as the test attestation
    // omits it. Ignore this case intentionally.
    // return false;
  }
  return true;
}