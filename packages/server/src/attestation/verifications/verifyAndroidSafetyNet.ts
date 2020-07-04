import base64url from 'base64url';

import type { AttestationStatement } from '../../helpers/decodeAttestationObject';

import toHash from '../../helpers/toHash';
import verifySignature from '../../helpers/verifySignature';
import getCertificateInfo from '../../helpers/getCertificateInfo';
import validateCertificatePath from '../../helpers/validateCertificatePath';
import convertASN1toPEM from '../../helpers/convertASN1toPEM';
import MetadataService from '../../metadata/metadataService';

type Options = {
  attStmt: AttestationStatement;
  clientDataHash: Buffer;
  authData: Buffer;
  aaguid: Buffer;
  verifyTimestampMS?: boolean;
};

/**
 * Verify an attestation response with fmt 'android-safetynet'
 */
export default async function verifyAttestationAndroidSafetyNet(
  options: Options,
): Promise<boolean> {
  const { attStmt, clientDataHash, authData, aaguid, verifyTimestampMS = true } = options;
  const { response, ver } = attStmt;

  if (!ver) {
    throw new Error('No ver value in attestation (SafetyNet)');
  }

  if (!response) {
    throw new Error('No response was included in attStmt by authenticator (SafetyNet)');
  }

  // Prepare to verify a JWT
  const jwt = response.toString('utf8');
  const jwtParts = jwt.split('.');

  const HEADER: SafetyNetJWTHeader = JSON.parse(base64url.decode(jwtParts[0]));
  const PAYLOAD: SafetyNetJWTPayload = JSON.parse(base64url.decode(jwtParts[1]));
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
      throw new Error(`Payload timestamp "${timestampPlusDelay}" has expired`);
    }
  }

  const nonceBase = Buffer.concat([authData, clientDataHash]);
  const nonceBuffer = toHash(nonceBase);
  const expectedNonce = nonceBuffer.toString('base64');

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
  const leafCert = convertASN1toPEM(HEADER.x5c[0]);
  const leafCertInfo = getCertificateInfo(leafCert);

  const { subject } = leafCertInfo;

  // Ensure the certificate was issued to this hostname
  // See https://developer.android.com/training/safetynet/attestation#verify-attestation-response
  if (subject.CN !== 'attest.android.com') {
    throw new Error('Certificate common name was not "attest.android.com" (SafetyNet)');
  }

  const statement = await MetadataService.getStatement(aaguid);
  if (statement) {
    // Try to validate the chain with each metadata root cert until we find one that works
    let validated = false;
    for (const rootCert of statement.attestationRootCertificates) {
      try {
        const path = [...HEADER.x5c, rootCert].map(convertASN1toPEM);
        validated = validateCertificatePath(path);
      } catch (err) {
        // Swallow the error for now
        validated = false;
      }

      // Don't continue if we've validated a full path
      if (validated) {
        break;
      }
    }

    if (!validated) {
      throw new Error(
        `Could not validate certificate path with any metadata root certificates (SafetyNet)`,
      );
    }
  } else {
    // Validate certificate path using a fixed global root cert
    const path = HEADER.x5c.concat([GlobalSignRootCAR2]).map(convertASN1toPEM);

    try {
      validateCertificatePath(path);
    } catch (err) {
      throw new Error(`${err} (SafetyNet)`);
    }
  }
  /**
   * END Verify Header
   */

  /**
   * START Verify Signature
   */
  const signatureBaseBuffer = Buffer.from(`${jwtParts[0]}.${jwtParts[1]}`);
  const signatureBuffer = base64url.toBuffer(SIGNATURE);

  const verified = verifySignature(signatureBuffer, signatureBaseBuffer, leafCert);
  /**
   * END Verify Signature
   */

  return verified;
}

/**
 * This "GS Root R2" root certificate was downloaded from https://pki.goog/gsr2/GSR2.crt
 * on 08/10/2019 and then run through `base64url.encode()` to get this representation.
 *
 * The certificate is valid until Dec 15, 2021
 */
const GlobalSignRootCAR2 =
  'MIIDujCCAqKgAwIBAgILBAAAAAABD4Ym5g0wDQYJKoZIhvcNAQEFBQAwTDEgMB4GA1UEC' +
  'xMXR2xvYmFsU2lnbiBSb290IENBIC0gUjIxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhc' +
  'NMDYxMjE1MDgwMDAwWhcNMjExMjE1MDgwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMjETMBEGA' +
  '1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKb' +
  'PJA6-Lm8omUVCxKs-IVSbC9N_hHD6ErPLv4dfxn-G07IwXNb9rfF73OX4YJYJkhD10FPe-3t-c4isUoh7SqbKSaZeqKeMW' +
  'hG8eoLrvozps6yWJQeXSpkqBy-0Hne_ig-1AnwblrjFuTosvNYSuetZfeLQBoZfXklqtTleiDTsvHgMCJiEbKjNS7SgfQx' +
  '5TfC4LcshytVsW33hoCmEofnTlEnLJGKRILzdC9XZzPnqJworc5HGnRusyMvo4KD0L5CLTfuwNhv2GXqF4G3yYROIXJ_gk' +
  'wpRl4pazq-r1feqCapgvdzZX99yqWATXgAByUr6P6TqBwMhAo6CygPCm48CAwEAAaOBnDCBmTAOBgNVHQ8BAf8EBAMCAQY' +
  'wDwYDVR0TAQH_BAUwAwEB_zAdBgNVHQ4EFgQUm-IHV2ccHsBqBt5ZtJot39wZhi4wNgYDVR0fBC8wLTAroCmgJ4YlaHR0c' +
  'DovL2NybC5nbG9iYWxzaWduLm5ldC9yb290LXIyLmNybDAfBgNVHSMEGDAWgBSb4gdXZxwewGoG3lm0mi3f3BmGLjANBgk' +
  'qhkiG9w0BAQUFAAOCAQEAmYFThxxol4aR7OBKuEQLq4GsJ0_WwbgcQ3izDJr86iw8bmEbTUsp9Z8FHSbBuOmDAGJFtqkIk' +
  '7mpM0sYmsL4h4hO291xNBrBVNpGP-DTKqttVCL1OmLNIG-6KYnX3ZHu01yiPqFbQfXf5WRDLenVOavSot-3i9DAgBkcRcA' +
  'tjOj4LaR0VknFBbVPFd5uRHg5h6h-u_N5GJG79G-dwfCMNYxdAfvDbbnvRG15RjF-Cv6pgsH_76tuIMRQyV-dTZsXjAzlA' +
  'cmgQWpzU_qlULRuJQ_7TBj0_VLZjmmx6BEP3ojY-x1J96relc8geMJgEtslQIxq_H5COEBkEveegeGTLg';

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
