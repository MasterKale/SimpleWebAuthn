import { AsnParser } from '@peculiar/asn1-schema';
import { Certificate } from '@peculiar/asn1-x509';

import type { AttestationStatement } from '../../helpers/decodeAttestationObject';
import validateCertificatePath from '../../helpers/validateCertificatePath';
import convertCertBufferToPEM from '../../helpers/convertCertBufferToPEM';
import toHash from '../../helpers/toHash';
import convertCOSEtoPKCS from '../../helpers/convertCOSEtoPKCS';

type Options = {
  attStmt: AttestationStatement;
  authData: Buffer;
  clientDataHash: Buffer;
  credentialPublicKey: Buffer;
  rootCertificates: string[];
};

export default async function verifyApple(options: Options): Promise<boolean> {
  const { attStmt, authData, clientDataHash, credentialPublicKey, rootCertificates } = options;
  const { x5c } = attStmt;

  if (!x5c) {
    throw new Error('No attestation certificate provided in attestation statement (Apple)');
  }

  /**
   * Verify certificate path
   */
  const certPath = x5c.map(convertCertBufferToPEM);

  try {
    await validateCertificatePath(certPath, rootCertificates);
  } catch (err) {
    throw new Error(`${err.message} (Apple)`);
  }

  /**
   * Compare nonce in certificate extension to computed nonce
   */
  const parsedCredCert = AsnParser.parse(x5c[0], Certificate);
  const { extensions, subjectPublicKeyInfo } = parsedCredCert.tbsCertificate;

  if (!extensions) {
    throw new Error('credCert missing extensions (Apple)');
  }

  const extCertNonce = extensions.find(ext => ext.extnID === '1.2.840.113635.100.8.2');

  if (!extCertNonce) {
    throw new Error('credCert missing "1.2.840.113635.100.8.2" extension (Apple)');
  }

  const nonceToHash = Buffer.concat([authData, clientDataHash]);
  const nonce = toHash(nonceToHash, 'SHA256');
  /**
   * Ignore the first six ASN.1 structure bytes that define the nonce as an OCTET STRING. Should
   * trim off <Buffer 30 24 a1 22 04 20>
   *
   * TODO: Try and get @peculiar (GitHub) to add a schema for "1.2.840.113635.100.8.2" when we
   * find out where it's defined (doesn't seem to be publicly documented at the moment...)
   */
  const extNonce = Buffer.from(extCertNonce.extnValue.buffer).slice(6);

  if (!nonce.equals(extNonce)) {
    throw new Error(`credCert nonce was not expected value (Apple)`);
  }

  /**
   * Verify credential public key matches the Subject Public Key of credCert
   */
  const credPubKeyPKCS = convertCOSEtoPKCS(credentialPublicKey);
  const credCertSubjectPublicKey = Buffer.from(subjectPublicKeyInfo.subjectPublicKey);

  if (!credPubKeyPKCS.equals(credCertSubjectPublicKey)) {
    throw new Error('Credential public key does not equal credCert public key (Apple)');
  }

  return true;
}
