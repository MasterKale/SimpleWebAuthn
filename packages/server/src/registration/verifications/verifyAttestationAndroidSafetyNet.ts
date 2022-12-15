import type { AttestationFormatVerifierOpts } from '../verifyRegistrationResponse';

import { toHash } from '../../helpers/toHash';
import { verifySignature } from '../../helpers/verifySignature';
import { getCertificateInfo } from '../../helpers/getCertificateInfo';
import { validateCertificatePath } from '../../helpers/validateCertificatePath';
import { convertCertBufferToPEM } from '../../helpers/convertCertBufferToPEM';
import { isoUint8Array, isoBase64URL } from '../../helpers/iso';
import { MetadataService } from '../../services/metadataService';
import { verifyAttestationWithMetadata } from '../../metadata/verifyAttestationWithMetadata';

/**
 * Verify an attestation response with fmt 'android-safetynet'
 */
export async function verifyAttestationAndroidSafetyNet(
  options: AttestationFormatVerifierOpts,
): Promise<boolean> {
  const {
    attStmt,
    clientDataHash,
    authData,
    aaguid,
    rootCertificates,
    verifyTimestampMS = true,
    credentialPublicKey,
  } = options;
  const alg = attStmt.get('alg');
  const response = attStmt.get('response');
  const ver = attStmt.get('ver');

  if (!ver) {
    throw new Error('No ver value in attestation (SafetyNet)');
  }

  if (!response) {
    throw new Error('No response was included in attStmt by authenticator (SafetyNet)');
  }

  // Prepare to verify a JWT
  const jwt = isoUint8Array.toUTF8String(response);
  const jwtParts = jwt.split('.');

  const HEADER: SafetyNetJWTHeader = JSON.parse(isoBase64URL.toString(jwtParts[0]));
  const PAYLOAD: SafetyNetJWTPayload = JSON.parse(isoBase64URL.toString(jwtParts[1]));
  const SIGNATURE: SafetyNetJWTSignature = jwtParts[2];

  /**
   * START Verify PAYLOAD
   */
  const { nonce, ctsProfileMatch, timestampMs } = PAYLOAD;

  if (verifyTimestampMS) {
    // Make sure timestamp is in the past
    let now = Date.now();
    if (timestampMs > Date.now()) {
      throw new Error(`Payload timestamp "${timestampMs}" was later than "${now}" (SafetyNet)`);
    }

    // Consider a SafetyNet attestation valid within a minute of it being performed
    const timestampPlusDelay = timestampMs + 60 * 1000;
    now = Date.now();
    if (timestampPlusDelay < now) {
      throw new Error(`Payload timestamp "${timestampPlusDelay}" has expired (SafetyNet)`);
    }
  }

  const nonceBase = isoUint8Array.concat([authData, clientDataHash]);
  const nonceBuffer = await toHash(nonceBase);
  const expectedNonce = isoBase64URL.fromBuffer(nonceBuffer, 'base64');

  if (nonce !== expectedNonce) {
    throw new Error('Could not verify payload nonce (SafetyNet)');
  }

  if (!ctsProfileMatch) {
    throw new Error('Could not verify device integrity (SafetyNet)');
  }
  /**
   * END Verify PAYLOAD
   */

  /**
   * START Verify Header
   */
  // `HEADER.x5c[0]` is definitely a base64 string
  const leafCertBuffer = isoBase64URL.toBuffer(HEADER.x5c[0], 'base64');
  const leafCertInfo = getCertificateInfo(leafCertBuffer);

  const { subject } = leafCertInfo;

  // Ensure the certificate was issued to this hostname
  // See https://developer.android.com/training/safetynet/attestation#verify-attestation-response
  if (subject.CN !== 'attest.android.com') {
    throw new Error('Certificate common name was not "attest.android.com" (SafetyNet)');
  }

  const statement = await MetadataService.getStatement(aaguid);
  if (statement) {
    try {
      await verifyAttestationWithMetadata({
        statement,
        credentialPublicKey,
        x5c: HEADER.x5c,
        attestationStatementAlg: alg,
      });
    } catch (err) {
      const _err = err as Error;
      throw new Error(`${_err.message} (SafetyNet)`);
    }
  } else {
    try {
      // Try validating the certificate path using the root certificates set via SettingsService
      await validateCertificatePath(HEADER.x5c.map(convertCertBufferToPEM), rootCertificates);
    } catch (err) {
      const _err = err as Error;
      throw new Error(`${_err.message} (SafetyNet)`);
    }
  }
  /**
   * END Verify Header
   */

  /**
   * START Verify Signature
   */
  const signatureBaseBuffer = isoUint8Array.fromUTF8String(`${jwtParts[0]}.${jwtParts[1]}`);
  const signatureBuffer = isoBase64URL.toBuffer(SIGNATURE);

  const verified = await verifySignature({
    signature: signatureBuffer,
    data: signatureBaseBuffer,
    x509Certificate: leafCertBuffer,
  });
  /**
   * END Verify Signature
   */

  return verified;
}

type SafetyNetJWTHeader = {
  alg: string;
  x5c: string[];
};

type SafetyNetJWTPayload = {
  nonce: string;
  timestampMs: number;
  apkPackageName: string;
  apkDigestSha256: string;
  ctsProfileMatch: boolean;
  apkCertificateDigestSha256: string[];
  basicIntegrity: boolean;
};

type SafetyNetJWTSignature = string;
