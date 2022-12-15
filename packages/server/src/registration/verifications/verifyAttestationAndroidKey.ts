import { AsnParser } from '@peculiar/asn1-schema';
import { Certificate } from '@peculiar/asn1-x509';
import { KeyDescription, id_ce_keyDescription } from '@peculiar/asn1-android';

import type { AttestationFormatVerifierOpts } from '../verifyRegistrationResponse';

import { convertCertBufferToPEM } from '../../helpers/convertCertBufferToPEM';
import { validateCertificatePath } from '../../helpers/validateCertificatePath';
import { verifySignature } from '../../helpers/verifySignature';
import { convertCOSEtoPKCS } from '../../helpers/convertCOSEtoPKCS';
import { isCOSEAlg } from '../../helpers/cose';
import { isoUint8Array } from '../../helpers/iso';
import { MetadataService } from '../../services/metadataService';
import { verifyAttestationWithMetadata } from '../../metadata/verifyAttestationWithMetadata';

/**
 * Verify an attestation response with fmt 'android-key'
 */
export async function verifyAttestationAndroidKey(
  options: AttestationFormatVerifierOpts,
): Promise<boolean> {
  const { authData, clientDataHash, attStmt, credentialPublicKey, aaguid, rootCertificates } =
    options;
  const x5c = attStmt.get('x5c');
  const sig = attStmt.get('sig');
  const alg = attStmt.get('alg');

  if (!x5c) {
    throw new Error('No attestation certificate provided in attestation statement (AndroidKey)');
  }

  if (!sig) {
    throw new Error('No attestation signature provided in attestation statement (AndroidKey)');
  }

  if (!alg) {
    throw new Error(`Attestation statement did not contain alg (AndroidKey)`);
  }

  if (!isCOSEAlg(alg)) {
    throw new Error(`Attestation statement contained invalid alg ${alg} (AndroidKey)`);
  }

  // Check that credentialPublicKey matches the public key in the attestation certificate
  // Find the public cert in the certificate as PKCS
  const parsedCert = AsnParser.parse(x5c[0], Certificate);
  const parsedCertPubKey = new Uint8Array(
    parsedCert.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey,
  );

  // Convert the credentialPublicKey to PKCS
  const credPubKeyPKCS = convertCOSEtoPKCS(credentialPublicKey);

  if (!isoUint8Array.areEqual(credPubKeyPKCS, parsedCertPubKey)) {
    throw new Error('Credential public key does not equal leaf cert public key (AndroidKey)');
  }

  // Find Android KeyStore Extension in certificate extensions
  const extKeyStore = parsedCert.tbsCertificate.extensions?.find(
    ext => ext.extnID === id_ce_keyDescription,
  );

  if (!extKeyStore) {
    throw new Error('Certificate did not contain extKeyStore (AndroidKey)');
  }

  const parsedExtKeyStore = AsnParser.parse(extKeyStore.extnValue, KeyDescription);

  // Verify extKeyStore values
  const { attestationChallenge, teeEnforced, softwareEnforced } = parsedExtKeyStore;

  if (!isoUint8Array.areEqual(new Uint8Array(attestationChallenge.buffer), clientDataHash)) {
    throw new Error('Attestation challenge was not equal to client data hash (AndroidKey)');
  }

  // Ensure that the key is strictly bound to the caller app identifier (shouldn't contain the
  // [600] tag)
  if (teeEnforced.allApplications !== undefined) {
    throw new Error('teeEnforced contained "allApplications [600]" tag (AndroidKey)');
  }

  if (softwareEnforced.allApplications !== undefined) {
    throw new Error('teeEnforced contained "allApplications [600]" tag (AndroidKey)');
  }

  const statement = await MetadataService.getStatement(aaguid);
  if (statement) {
    try {
      await verifyAttestationWithMetadata({
        statement,
        credentialPublicKey,
        x5c,
        attestationStatementAlg: alg,
      });
    } catch (err) {
      const _err = err as Error;
      throw new Error(`${_err.message} (AndroidKey)`);
    }
  } else {
    try {
      // Try validating the certificate path using the root certificates set via SettingsService
      await validateCertificatePath(x5c.map(convertCertBufferToPEM), rootCertificates);
    } catch (err) {
      const _err = err as Error;
      throw new Error(`${_err.message} (AndroidKey)`);
    }
  }

  const signatureBase = isoUint8Array.concat([authData, clientDataHash]);

  return verifySignature({
    signature: sig,
    data: signatureBase,
    x509Certificate: x5c[0],
    hashAlgorithm: alg,
  });
}
