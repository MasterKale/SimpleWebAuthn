import base64url from 'base64url';

import { AttestationObject, VerifiedAttestation } from "@types";
import toHash from "@helpers/toHash";
import verifySignature from '@helpers/verifySignature';
import parseAttestationAuthData from '@helpers/parseAttestationAuthData';
import convertCOSEECDHAtoPKCS from '@helpers/convertCOSEECDHAtoPKCS';
import getCertificateInfo from '@helpers/getCertificateInfo';


export default function verifyAttestationAndroidSafetyNet(
  attestationObject: AttestationObject,
  base64ClientDataJSON: string,
): VerifiedAttestation {
  const { attStmt, authData, fmt } = attestationObject;

  if (!attStmt.response) {
    throw new Error('No response was included in attStmt by authenticator');
  }

  // Prepare to verify a JWT
  const jwt = attStmt.response.toString('utf8');
  const jwtParts = jwt.split('.');

  const HEADER = JSON.parse(base64url.decode(jwtParts[0]));
  const PAYLOAD = JSON.parse(base64url.decode(jwtParts[1]));
  const SIGNATURE = jwtParts[2];

  console.debug('HEADER:', HEADER);
  console.debug('PAYLOAD:', PAYLOAD);
  console.debug('SIGNATURE:', SIGNATURE);

  /**
   * START Verify PAYLOAD
   */
  const { nonce, ctsProfileMatch } = PAYLOAD;
  const clientDataHash = toHash(base64url.toBuffer(base64ClientDataJSON));

  const nonceBase = Buffer.concat([
    authData,
    clientDataHash,
  ]);
  const nonceBuffer = toHash(nonceBase);
  const expectedNonce = nonceBuffer.toString('base64');

  if (nonce !== expectedNonce) {
    console.error('Payload nonce was not the expected value!');
    console.debug('payload nonce:', PAYLOAD.nonce);
    console.debug('expected nonce:', expectedNonce);
    throw new Error('Could not verify response payload nonce');
  }

  if (!ctsProfileMatch) {
    console.error('ctsProfileMatch was false!');
    console.debug('ctsProfileMatch:', ctsProfileMatch);
    throw new Error('Could not verify response payload profile');
  }
  /**
   * END Verify PAYLOAD
   */

  /**
   * START Verify Header
   */
  // Generate an array of certs constituting a full certificate chain
  const fullpathCert = HEADER.x5c.concat([GlobalSignRootCAR2]).map((cert: string) => {
    let pem = '';
    // Take a string of characters and chop them up into 64-char lines (just like a PEM cert)
    for (let i = 0; i < cert.length; i += 64) {
      pem += `${cert.slice(i, i + 64)}\n`;
    }

    return `-----BEGIN CERTIFICATE-----\n${pem}-----END CERTIFICATE-----`;
  });

  console.debug('fullpathCert:', fullpathCert);

  const certificate = fullpathCert[0];

  const commonCertInfo = getCertificateInfo(certificate);
  console.debug('commonCertInfo:', commonCertInfo);

  const { subject } = commonCertInfo;

  // TODO: Find out where this CN string is specified and if it might change
  if (subject.CN !== 'attest.android.com') {
    console.error('common name was not "attest.android.com"');
    throw new Error('Could not verify certificate common name');
  }

  // TODO: Re-investigate this if we decide to "use MDS or Metadata Statements"
  // WebauthnService.validateCertificatePath(fullpathCert);
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
  };
  /**
   * END Verify Signature
   */


  if (toReturn.verified) {
    const authDataStruct = parseAttestationAuthData(authData);
    console.debug('authDataStruct:', authDataStruct);
    const { counter, credentialID, COSEPublicKey } = authDataStruct;

    if (!COSEPublicKey) {
      throw new Error('No public key was provided by authenticator');
    }

    if (!credentialID) {
      throw new Error('No credential ID was provided by authenticator');
    }

    const publicKey = convertCOSEECDHAtoPKCS(COSEPublicKey);

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
const GlobalSignRootCAR2 = 'MIIDujCCAqKgAwIBAgILBAAAAAABD4Ym5g0wDQYJKoZIhvcNAQEFBQAwTDEgMB4GA1UEC' +
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
