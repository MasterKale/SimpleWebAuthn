import base64url from "base64url";
import { toHash } from "../helpers/toHash";
import { verifySignature } from "../helpers/verifySignature";
import { DevicePublicKeyAuthenticatorOutput } from "../helpers/decodeAuthenticatorExtensions";
import { SettingsService } from "../services/settingsService";
import { AttestationFormatVerifierOpts } from "../registration/verifyRegistrationResponse";
import { parseAuthenticatorData } from "../helpers/parseAuthenticatorData";
import { verifyAttestationFIDOU2F } from '../registration/verifications/verifyAttestationFIDOU2F';
import { verifyAttestationPacked } from '../registration/verifications/verifyAttestationPacked';
import { verifyAttestationAndroidSafetyNet } from '../registration/verifications/verifyAttestationAndroidSafetyNet';
import { verifyAttestationTPM } from '../registration//verifications/tpm/verifyAttestationTPM';
import { verifyAttestationAndroidKey } from '../registration/verifications/verifyAttestationAndroidKey';
import { verifyAttestationApple } from '../registration/verifications/verifyAttestationApple';

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
 * @returns Promise<boolean>
 */
export async function verifyDpkSignature(
  clientDataJSON: string,
  authData: Buffer,
  devicePubKey: DevicePublicKeyAuthenticatorOutput,
  signature: Buffer,
): Promise<boolean> {
  const clientDataHash = toHash(base64url.toBuffer(clientDataJSON));
  const parsedAuthData = parseAuthenticatorData(authData);
  const { rpIdHash, credentialID } = parsedAuthData;
  
  if (!credentialID) {
    // `authData` without `credentialID` can't be verified.
    return false;
  }

  const nonce = devicePubKey.nonce ? devicePubKey.nonce : Buffer.from('');
  const signatureBase = Buffer.concat([credentialID, clientDataHash, nonce]);
  const credentialPublicKey = devicePubKey.dpk;

  // If `fmt` and `attStmt` are not included, skip verification.
  if (devicePubKey.fmt && devicePubKey.attStmt) {
    const rootCertificates = SettingsService.getRootCertificates({ identifier: devicePubKey.fmt });

    // Prepare arguments to pass to the relevant verification method
    const verifierOpts: AttestationFormatVerifierOpts = {
      aaguid: devicePubKey.aaguid,
      attStmt: devicePubKey.attStmt,
      authData,
      clientDataHash,
      credentialID,
      credentialPublicKey,
      rootCertificates,
      rpIdHash,
    };

    // TODO: Implement logics to verify attestation signatures
    let verified = false;
    if (devicePubKey.fmt === 'fido-u2f') {
      verified = await verifyAttestationFIDOU2F(verifierOpts);
    } else if (devicePubKey.fmt === 'packed') {
      verified = await verifyAttestationPacked(verifierOpts);
    } else if (devicePubKey.fmt === 'android-safetynet') {
      verified = await verifyAttestationAndroidSafetyNet(verifierOpts);
    } else if (devicePubKey.fmt === 'android-key') {
      verified = await verifyAttestationAndroidKey(verifierOpts);
    } else if (devicePubKey.fmt === 'tpm') {
      verified = await verifyAttestationTPM(verifierOpts);
    } else if (devicePubKey.fmt === 'apple') {
      verified = await verifyAttestationApple(verifierOpts);
    } else if (devicePubKey.fmt === 'none') {
      if (Object.keys(devicePubKey.attStmt).length > 0) {
        throw new Error('None attestation had unexpected attestation statement');
      }
      // This is the weaker of the attestations, so there's nothing else to really check
      verified = true;
    } else {
      throw new Error(`Unsupported Attestation Format: ${devicePubKey.fmt}`);
    }
    if (!verified) {
      return false;
    }
  }

  return verifySignature({ signature, signatureBase, credentialPublicKey });
}

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
  if ((devicePubKey.fmt || expectedDPK.fmt) &&
      devicePubKey.fmt !== expectedDPK.fmt) {
    return false;
  }
  if (devicePubKey.attStmt ||
      expectedDPK.attStmt) {
    // TODO: Examine if comparing properties is a good idea.
    return false;
  }
  return true;
}
