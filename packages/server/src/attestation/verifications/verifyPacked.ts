import elliptic from 'elliptic';
import NodeRSA from 'node-rsa';

import type { AttestationStatement } from '../../helpers/decodeAttestationObject';

import convertCOSEtoPKCS, {
  COSEKEYS,
  COSEALGHASH,
  COSECRV,
  COSEKTY,
  COSERSASCHEME,
} from '../../helpers/convertCOSEtoPKCS';
import toHash from '../../helpers/toHash';
import convertASN1toPEM from '../../helpers/convertASN1toPEM';
import getCertificateInfo from '../../helpers/getCertificateInfo';
import verifySignature from '../../helpers/verifySignature';
import decodeCredentialPublicKey from '../../helpers/decodeCredentialPublicKey';

type Options = {
  attStmt: AttestationStatement;
  clientDataHash: Buffer;
  authData: Buffer;
  credentialPublicKey: Buffer;
  aaguid: Buffer;
};

/**
 * Verify an attestation response with fmt 'packed'
 */
export default function verifyAttestationPacked(options: Options): boolean {
  const { attStmt, clientDataHash, authData, credentialPublicKey, aaguid } = options;

  const { sig, x5c, alg } = attStmt;

  if (!sig) {
    throw new Error('No attestation signature provided in attestation statement (Packed)');
  }

  if (Number.isNaN(Number(alg))) {
    throw new Error(`Attestation Statement alg "${alg}" is not a number (Packed)`);
  }

  const signatureBase = Buffer.concat([authData, clientDataHash]);

  let verified = false;
  const pkcsPublicKey = convertCOSEtoPKCS(credentialPublicKey);

  if (x5c) {
    const leafCert = convertASN1toPEM(x5c[0]);
    const { subject, basicConstraintsCA, version, notBefore, notAfter } = getCertificateInfo(
      leafCert,
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

    if (version !== 3) {
      throw new Error('Certificate version was not `3` (ASN.1 value of 2) (Packed|Full)');
    }

    let now = new Date();
    if (notBefore > now) {
      throw new Error(`Certificate not good before "${notBefore.toString()}"`);
    }

    now = new Date();
    if (notAfter < now) {
      throw new Error(`Certificate not good after "${notAfter.toString()}"`);
    }

    // TODO: If certificate contains id-fido-gen-ce-aaguid(1.3.6.1.4.1.45724.1.1.4) extension, check
    // that it’s value is set to the same AAGUID as in authData.

    // TODO: Parse authData, and verify that authData.publicKey algorithm set to the corresponding
    // algorithm to the one set in metadata statement.

    // TODO: For each attestationRoot in metadata.attestationRootCertificates, generate verification
    // chain verifX5C by appending attestationRoot to the x5c. Try verifying verifyX5C. If fail try
    // next attestationRoot. If no attestationRoots left to try, return error.

    verified = verifySignature(sig, signatureBase, leafCert);
  } else {
    const cosePublicKey = decodeCredentialPublicKey(credentialPublicKey);

    const kty = cosePublicKey.get(COSEKEYS.kty);

    if (!kty) {
      throw new Error('COSE public key was missing kty (Packed|Self)');
    }

    const hashAlg: string = COSEALGHASH[alg as number];

    if (kty === COSEKTY.EC2) {
      const crv = cosePublicKey.get(COSEKEYS.crv);

      if (!crv) {
        throw new Error('COSE public key was missing kty crv (Packed|EC2)');
      }

      const signatureBaseHash = toHash(signatureBase, hashAlg);

      /**
       * Instantiating the curve here is _very_ computationally heavy - a bit of profiling
       * (in compiled JS, not TS) reported an average of ~125ms to execute this line. The elliptic
       * README states, "better do it once and reuse it", so maybe there's a better way to handle
       * this in a server context, when we can re-use an existing instance.
       *
       * For now, it's worth noting that this line is probably the reason why it can take
       * 5-6 seconds to run tests.
       */
      const ec = new elliptic.ec(COSECRV[crv as number]);
      const key = ec.keyFromPublic(pkcsPublicKey);

      verified = key.verify(signatureBaseHash, sig);
    } else if (kty === COSEKTY.RSA) {
      const n = cosePublicKey.get(COSEKEYS.n);

      if (!n) {
        throw new Error('COSE public key was missing n (Packed|RSA)');
      }

      const signingScheme = COSERSASCHEME[alg as number];

      // TODO: Verify this works
      const key = new NodeRSA();
      key.setOptions({ signingScheme });
      key.importKey(
        {
          n: n as Buffer,
          e: 65537,
        },
        'components-public',
      );

      verified = key.verify(signatureBase, sig);
    } else if (kty === COSEKTY.OKP) {
      const x = cosePublicKey.get(COSEKEYS.x);

      if (!x) {
        throw new Error('COSE public key was missing x (Packed|OKP)');
      }

      const signatureBaseHash = toHash(signatureBase, hashAlg);

      const key = new elliptic.eddsa('ed25519');
      key.keyFromPublic(x as Buffer);

      // TODO: is `publicKey` right here?
      verified = key.verify(signatureBaseHash, sig, pkcsPublicKey);
    }
  }

  return verified;
}
