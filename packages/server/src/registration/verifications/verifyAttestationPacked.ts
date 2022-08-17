import type { AttestationFormatVerifierOpts } from '../verifyRegistrationResponse';

import { COSEALGHASH } from '../../helpers/convertCOSEtoPKCS';
import { convertCertBufferToPEM } from '../../helpers/convertCertBufferToPEM';
import { validateCertificatePath } from '../../helpers/validateCertificatePath';
import { getCertificateInfo } from '../../helpers/getCertificateInfo';
import { verifySignature } from '../../helpers/verifySignature';
import { MetadataService } from '../../services/metadataService';
import { verifyAttestationWithMetadata } from '../../metadata/verifyAttestationWithMetadata';

/**
 * Verify an attestation response with fmt 'packed'
 */
export async function verifyAttestationPacked(
  options: AttestationFormatVerifierOpts,
): Promise<boolean> {
  const { attStmt, clientDataHash, authData, credentialPublicKey, aaguid, rootCertificates } =
    options;

  const { sig, x5c, alg } = attStmt;

  if (!sig) {
    throw new Error('No attestation signature provided in attestation statement (Packed)');
  }

  if (typeof alg !== 'number') {
    throw new Error(`Attestation Statement alg "${alg}" is not a number (Packed)`);
  }

  const signatureBase = Buffer.concat([authData, clientDataHash]);

  let verified = false;

  if (x5c) {
    const { subject, basicConstraintsCA, version, notBefore, notAfter } = getCertificateInfo(
      x5c[0],
    );

    const { OU, CN, O, C } = subject;

    if (OU !== 'Authenticator Attestation') {
      throw new Error('Certificate OU was not "Authenticator Attestation" (Packed|Full)');
    }

    if (!CN) {
      throw new Error('Certificate CN was empty (Packed|Full)');
    }

    if (!O) {
      throw new Error('Certificate O was empty (Packed|Full)');
    }

    if (!C || C.length !== 2) {
      throw new Error('Certificate C was not two-character ISO 3166 code (Packed|Full)');
    }

    if (basicConstraintsCA) {
      throw new Error('Certificate basic constraints CA was not `false` (Packed|Full)');
    }

    if (version !== 2) {
      throw new Error('Certificate version was not `3` (ASN.1 value of 2) (Packed|Full)');
    }

    let now = new Date();
    if (notBefore > now) {
      throw new Error(`Certificate not good before "${notBefore.toString()}" (Packed|Full)`);
    }

    now = new Date();
    if (notAfter < now) {
      throw new Error(`Certificate not good after "${notAfter.toString()}" (Packed|Full)`);
    }

    // TODO: If certificate contains id-fido-gen-ce-aaguid(1.3.6.1.4.1.45724.1.1.4) extension, check
    // that it’s value is set to the same AAGUID as in authData.

    // If available, validate attestation alg and x5c with info in the metadata statement
    const statement = await MetadataService.getStatement(aaguid);
    if (statement) {
      // The presence of x5c means this is a full attestation. Check to see if attestationTypes
      // includes packed attestations.
      if (statement.attestationTypes.indexOf('basic_full') < 0) {
        throw new Error('Metadata does not indicate support for full attestations (Packed|Full)');
      }

      try {
        await verifyAttestationWithMetadata({
          statement,
          credentialPublicKey,
          x5c,
          attestationStatementAlg: alg,
        });
      } catch (err) {
        const _err = err as Error;
        throw new Error(`${_err.message} (Packed|Full)`);
      }
    } else {
      try {
        // Try validating the certificate path using the root certificates set via SettingsService
        await validateCertificatePath(x5c.map(convertCertBufferToPEM), rootCertificates);
      } catch (err) {
        const _err = err as Error;
        throw new Error(`${_err.message} (Packed|Full)`);
      }
    }

    verified = await verifySignature({
      signature: sig,
      signatureBase,
      leafCert: x5c[0],
    });
  } else {
    const hashAlg: string = COSEALGHASH[alg as number];

    verified = await verifySignature({
      signature: sig,
      signatureBase,
      credentialPublicKey,
      hashAlgorithm: hashAlg
    });
  }

  return verified;
}
