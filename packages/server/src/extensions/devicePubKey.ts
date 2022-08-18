import base64url from "base64url";
import { toHash } from "../helpers/toHash";
import { verifySignature } from "../helpers/verifySignature";
import { convertPublicKeyToPEM } from "../helpers/convertPublicKeyToPEM";
import { DevicePublicKeyAuthenticatorOutput } from "helpers/decodeAuthenticatorExtensions";

/**
 * https://pr-preview.s3.amazonaws.com/w3c/webauthn/pull/1663.html#sctn-device-publickey-extension-verification-create
 * 3. Verify that `signature` is a valid signature over the assertion signature
 *    input by the device public key *dpk*. (The signature algorithm is the same
 *    as for the user credential.)
 * @param credentialID 
 * @param clientDataJSON 
 * @param nonce 
 * @param dpk 
 * @param signature 
 * @returns 
 */
export function verifyDpkSignature(
  credentialID: string,
  clientDataJSON: string,
  devicePubKey: DevicePublicKeyAuthenticatorOutput,
  signature: Buffer,
): boolean {
  const rawId = base64url.toBuffer(credentialID);
  const clientDataHash = toHash(base64url.toBuffer(clientDataJSON));
  const nonce = devicePubKey.nonce ? devicePubKey.nonce : Buffer.from('');
  const signatureBase = Buffer.concat([rawId, clientDataHash, nonce]);
  const publicKey = convertPublicKeyToPEM(devicePubKey.dpk);

  // TODO: Implement a logic to verify attestation signatures

  return verifySignature(signature, signatureBase, publicKey);
}

/**
 * https://pr-preview.s3.amazonaws.com/w3c/webauthn/pull/1663.html#sctn-device-publickey-extension-verification-get
 * 4. If the Relying Party's user account mapped to the *credential*.id in play
 *    (i.e., for the user being authenticated) holds `aaguid`, `dpk`, `scope`,
 *    `fmt`, and `attStmt` values corresponding to the extracted
 *    *attObjForDevicePublicKey* fields, then perform binary equality checks
 *    between the corresponding stored values and the extracted field values.
 *    The Relying Party may have more than one set of `{aaguid, dpk, scope, fmt,
 *    attStmt}` values mapped to the user account and *credential*.id pair and
 *    each set must be checked.
 * @param devicePubKey 
 * @param expectedDPK 
 * @returns 
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
  if (devicePubKey.fmt &&
      expectedDPK.fmt &&
      devicePubKey.fmt === expectedDPK.fmt &&
      !devicePubKey.fmt.equals(expectedDPK.fmt)) {
    return false;
  }
  if (devicePubKey.attStmt &&
      expectedDPK.attStmt &&
      devicePubKey.attStmt === expectedDPK.attStmt &&
      !devicePubKey.attStmt.equals(expectedDPK.attStmt)) {
    return false;
  }
  return true;
}
