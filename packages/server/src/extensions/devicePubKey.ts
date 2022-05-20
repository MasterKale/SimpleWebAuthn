import cbor from 'cbor';
import base64url from 'base64url';
import { AttestationFormat, AttestationStatement } from '../helpers/decodeAttestationObject';
import { RegistrationCredentialJSON } from '@simplewebauthn/typescript-types';
import { CredentialPropertiesOutput, UvmEntries } from '@simplewebauthn/typescript-types';
import { parseAuthenticatorData, verifySignature, decodeCredentialPublicKey } from 'helpers';
import { COSEKEYS } from '../helpers/convertCOSEtoPKCS';

export function decodeAttObjForDevicePublicKey(attObjForDevicePublicKey: Buffer): AttObjForDevicePublicKey {
  const toCBOR: AttObjForDevicePublicKey = cbor.decodeAllSync(attObjForDevicePublicKey)[0];
  return toCBOR;
}

export async function verifyAttObjForDevicePublicKey(
  credential: RegistrationCredentialJSON,
  attObjForDevicePublicKey: AttObjForDevicePublicKey,
  authData: Buffer,
  hash: Buffer
): Promise<boolean> {
  const { credentialID, credentialPublicKey } = parseAuthenticatorData(authData);
  if (!credentialID) {
    throw new Error('No credential ID was provided by authenticator');
  }
  if (!credentialPublicKey) {
    throw new Error('No credential public key was provided by authenticator');
  }
  const decodedPublicKey = decodeCredentialPublicKey(credentialPublicKey);
  const alg = decodedPublicKey.get(COSEKEYS.alg);

  if (typeof alg !== 'number') {
    throw new Error('Credential public key was missing numeric alg');
  }

  // Make sure the key algorithm is one we specified within the registration options
  if (!supportedAlgorithmIDs.includes(alg as number)) {
    const supported = supportedAlgorithmIDs.join(', ');
    throw new Error(`Unexpected public key alg "${alg}", expected one of "${supported}"`);
  }

  const rootCertificates = settingsService.getRootCertificates({ identifier: fmt });

  const { sig, aaguid, dpk, nonce, fmt, attStmt } = attObjForDevicePublicKey;

  // Verify that `sig` is a valid signature over the concatenation of `hash` and
  // `credentialId` using the device public key `dpk` (the signature algorithm
  // is indicated by dpk’s "alg" COSEAlgorithmIdentifier value).
  const signatureBase = Buffer.concat([hash, credentialID]);
  verifySignature(sig, signatureBase, dpk);

  // Verify that `attStmt` is a correct attestation statement, conveying a valid
  // attestation signature, by using the attestation statement format `fmt`’s
  // verification procedure given `attStmt`, although substituting `aaguid`’s
  // value for `authenticatorData`, and substituting the concatenation of
  // `dpk`’s value and `nonce`’s value for `clientDataHash` in the attestation
  // statement format's verification procedure inputs.
  // Note: If `fmt’`s value is "none" there is no attestation signature to
  // verify.
  const clientDataHash = Buffer.concat([dpk, nonce]);

  // Prepare arguments to pass to the relevant verification method
  const verifierOpts: AttestationFormatVerifierOpts = {
    aaguid,
    attStmt,
    authData,
    clientDataHash,
    credentialID,
    credentialPublicKey,
    rootCertificates,
    rpIdHash,
  };

  /**
   * Verification can only be performed when attestation = 'direct'
   */
  let verified = false;
  if (fmt === 'fido-u2f') {
    verified = await verifyFIDOU2F(verifierOpts);
  } else if (fmt === 'packed') {
    verified = await verifyPacked(verifierOpts);
  } else if (fmt === 'android-safetynet') {
    verified = await verifyAndroidSafetynet(verifierOpts);
  } else if (fmt === 'android-key') {
    verified = await verifyAndroidKey(verifierOpts);
  } else if (fmt === 'tpm') {
    verified = await verifyTPM(verifierOpts);
  } else if (fmt === 'apple') {
    verified = await verifyApple(verifierOpts);
  } else if (fmt === 'none') {
    if (Object.keys(attStmt).length > 0) {
      throw new Error('None attestation had unexpected attestation statement');
    }
    // This is the weaker of the attestations, so there's nothing else to really check
    verified = true;
  } else {
    throw new Error(`Unsupported Attestation Format: ${fmt}`);
  }


  // Return the `aaguid`, `dpk`, `scope`, `fmt`, `attStmt` values indexed to the
  // `credential.id`.

  return true;
}

export type AttObjForDevicePublicKey = {
  sig: Buffer;
  aaguid: Buffer;
  dpk: Buffer;
  scope: number;
  nonce: Buffer;
  fmt: AttestationFormat;
  attStmt: AttestationStatement;
};

export type AuthenticationExtensionsClientOutputs = {
  appid?: boolean;
  credProps?: CredentialPropertiesOutput;
  uvm?: UvmEntries;
  devicePubKey?: AttObjForDevicePublicKey;
};
