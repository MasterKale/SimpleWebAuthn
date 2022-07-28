import type { AttestationFormatVerifierOpts } from '../verifyRegistrationResponse';

import { convertCOSEtoPKCS } from '../../helpers/convertCOSEtoPKCS';
import { convertCertBufferToPEM } from '../../helpers/convertCertBufferToPEM';
import { validateCertificatePath } from '../../helpers/validateCertificatePath';
import { verifySignature } from '../../helpers/verifySignature';

/**
 * Verify an attestation response with fmt 'fido-u2f'
 */
export async function verifyAttestationFIDOU2F(
  options: AttestationFormatVerifierOpts,
): Promise<boolean> {
  const {
    attStmt,
    clientDataHash,
    rpIdHash,
    credentialID,
    credentialPublicKey,
    aaguid = '',
    rootCertificates,
  } = options;

  const reservedByte = Buffer.from([0x00]);
  const publicKey = convertCOSEtoPKCS(credentialPublicKey);

  const signatureBase = Buffer.concat([
    reservedByte,
    rpIdHash,
    clientDataHash,
    credentialID,
    publicKey,
  ]);

  const { sig, x5c } = attStmt;

  if (!x5c) {
    throw new Error('No attestation certificate provided in attestation statement (FIDOU2F)');
  }

  if (!sig) {
    throw new Error('No attestation signature provided in attestation statement (FIDOU2F)');
  }

  // FIDO spec says that aaguid _must_ equal 0x00 here to be legit
  const aaguidToHex = Number.parseInt(aaguid.toString('hex'), 16);
  if (aaguidToHex !== 0x00) {
    throw new Error(`AAGUID "${aaguidToHex}" was not expected value`);
  }

  try {
    // Try validating the certificate path using the root certificates set via SettingsService
    await validateCertificatePath(x5c.map(convertCertBufferToPEM), rootCertificates);
  } catch (err) {
    const _err = err as Error;
    throw new Error(`${_err.message} (FIDOU2F)`);
  }

  const leafCertPEM = convertCertBufferToPEM(x5c[0]);

  return verifySignature(sig, signatureBase, leafCertPEM);
}
