import base64url from 'base64url';

import type { AttestationObject } from '../../helpers/decodeAttestationObject';
import type { VerifiedAttestation } from '../verifyAttestationResponse';

import toHash from '../../helpers/toHash';
import verifySignature from '../../helpers/verifySignature';
import convertCOSEtoPKCS from '../../helpers/convertCOSEtoPKCS';
import getCertificateInfo from '../../helpers/getCertificateInfo';
import parseAuthenticatorData from '../../helpers/parseAuthenticatorData';

/**
 * Verify an attestation response with fmt 'android-safetynet'
 */
export default function verifyAttestationAndroidSafetyNet(
  attestationObject: AttestationObject,
  base64ClientDataJSON: string,
): VerifiedAttestation {
  const { attStmt, authData, fmt } = attestationObject;
  const authDataStruct = parseAuthenticatorData(authData);
  const { counter, credentialID, COSEPublicKey, flags } = authDataStruct;

  if (!flags.up) {
    throw new Error('User was not present for attestation (None)');
  }

  if (!COSEPublicKey) {
    throw new Error('No public key was provided by authenticator (SafetyNet)');
  }

  if (!credentialID) {
    throw new Error('No credential ID was provided by authenticator (SafetyNet)');
  }

  if (!attStmt.response) {
    throw new Error('No response was included in attStmt by authenticator (SafetyNet)');
  }

  // Prepare to verify a JWT
  const jwt = attStmt.response.toString('utf8');
  const jwtParts = jwt.split('.');

  const HEADER: SafetyNetJWTHeader = JSON.parse(base64url.decode(jwtParts[0]));
  const PAYLOAD: SafetyNetJWTPayload = JSON.parse(base64url.decode(jwtParts[1]));
  const SIGNATURE: SafetyNetJWTSignature = jwtParts[2];

  /**
   * START Verify PAYLOAD
   */
  const { nonce, ctsProfileMatch } = PAYLOAD;
  const clientDataHash = toHash(base64url.toBuffer(base64ClientDataJSON));

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
  // Generate an array of certs constituting a full certificate chain
  const fullpathCert = HEADER.x5c.concat([GlobalSignRootCAR2]).map(cert => {
    let pem = '';
    // Take a string of characters and chop them up into 64-char lines (just like a PEM cert)
    for (let i = 0; i < cert.length; i += 64) {
      pem += `${cert.slice(i, i + 64)}\n`;
    }

    return `-----BEGIN CERTIFICATE-----\n${pem}-----END CERTIFICATE-----`;
  });

  const certificate = fullpathCert[0];

  const commonCertInfo = getCertificateInfo(certificate);

  const { subject } = commonCertInfo;

  // TODO: Find out where this CN string is specified and if it might change
  if (subject.CN !== 'attest.android.com') {
    throw new Error('Certificate common name was not "attest.android.com" (SafetyNet)');
  }

  // TODO: Re-investigate this if we decide to "use MDS or Metadata Statements"
  // validateCertificatePath(fullpathCert);
  /**
   * END Verify Header
   */

  /**
   * START Verify Signature
   */
  const signatureBaseBuffer = Buffer.from(`${jwtParts[0]}.${jwtParts[1]}`);
  const signatureBuffer = base64url.toBuffer(SIGNATURE);

  const toReturn: VerifiedAttestation = {
    verified: verifySignature(signatureBuffer, signatureBaseBuffer, certificate),
    userVerified: false,
  };
  /**
   * END Verify Signature
   */

  if (toReturn.verified) {
    toReturn.userVerified = flags.uv;

    const publicKey = convertCOSEtoPKCS(COSEPublicKey);

    toReturn.authenticatorInfo = {
      fmt,
      counter,
      base64PublicKey: base64url.encode(publicKey),
      base64CredentialID: base64url.encode(credentialID),
    };
  }

  return toReturn;
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
  alg: 'string';
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
