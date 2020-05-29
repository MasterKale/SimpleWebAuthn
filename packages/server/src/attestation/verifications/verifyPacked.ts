import base64url from 'base64url';
import cbor from 'cbor';
import elliptic from 'elliptic';
import NodeRSA, { SigningSchemeHash } from 'node-rsa';
import {
  AttestationObject,
  VerifiedAttestation,
  COSEKEYS,
  COSEPublicKey as COSEPublicKeyType,
} from '@simplewebauthn/typescript-types';

import convertCOSEtoPKCS from '../../helpers/convertCOSEtoPKCS';
import toHash from '../../helpers/toHash';
import convertASN1toPEM from '../../helpers/convertASN1toPEM';
import getCertificateInfo from '../../helpers/getCertificateInfo';
import verifySignature from '../../helpers/verifySignature';
import parseAuthenticatorData from '../../helpers/parseAuthenticatorData';

/**
 * Verify an attestation response with fmt 'packed'
 */
export default function verifyAttestationPacked(
  attestationObject: AttestationObject,
  base64ClientDataJSON: string,
): VerifiedAttestation {
  const { fmt, authData, attStmt } = attestationObject;
  const { sig, x5c } = attStmt;

  const authDataStruct = parseAuthenticatorData(authData);

  const { COSEPublicKey, counter, credentialID, flags } = authDataStruct;

  if (!flags.up) {
    throw new Error('User was not present for attestation (Packed)');
  }

  if (!COSEPublicKey) {
    throw new Error('No public key was provided by authenticator (Packed)');
  }

  if (!credentialID) {
    throw new Error('No credential ID was provided by authenticator (Packed)');
  }

  if (!sig) {
    throw new Error('No attestation signature provided in attestation statement (Packed)');
  }

  const clientDataHash = toHash(base64url.toBuffer(base64ClientDataJSON));

  const signatureBase = Buffer.concat([authData, clientDataHash]);

  const toReturn: VerifiedAttestation = {
    verified: false,
    userVerified: flags.uv,
  };
  const publicKey = convertCOSEtoPKCS(COSEPublicKey);

  if (x5c) {
    const leafCert = convertASN1toPEM(x5c[0]);
    const leafCertInfo = getCertificateInfo(leafCert);

    const { subject, basicConstraintsCA, version } = leafCertInfo;
    const { OU, CN, O, C } = subject;

    if (OU !== 'Authenticator Attestation') {
      throw new Error('Batch certificate OU was not "Authenticator Attestation" (Packed|Full');
    }

    if (!CN) {
      throw new Error('Batch certificate CN was empty (Packed|Full');
    }

    if (!O) {
      throw new Error('Batch certificate CN was empty (Packed|Full');
    }

    if (!C || C.length !== 2) {
      throw new Error('Batch certificate C was not two-character ISO 3166 code (Packed|Full');
    }

    if (basicConstraintsCA) {
      throw new Error('Batch certificate basic constraints CA was not `false` (Packed|Full');
    }

    if (version !== 3) {
      throw new Error('Batch certificate version was not `3` (ASN.1 value of 2) (Packed|Full');
    }

    toReturn.verified = verifySignature(sig, signatureBase, leafCert);
  } else {
    const cosePublicKey: COSEPublicKeyType = cbor.decodeAllSync(COSEPublicKey)[0];

    const kty = cosePublicKey.get(COSEKEYS.kty);
    const alg = cosePublicKey.get(COSEKEYS.alg);

    if (!alg) {
      throw new Error('COSE public key was missing alg (Packed|Self)');
    }

    if (!kty) {
      throw new Error('COSE public key was missing kty (Packed|Self)');
    }

    const hashAlg: string = COSEALGHASH[alg as number];

    if (kty === COSEKTY.EC2) {
      const crv = cosePublicKey.get(COSEKEYS.crv);

      if (!crv) {
        throw new Error('COSE public key was missing kty crv (Packed|EC2)');
      }

      const pkcsPublicKey = convertCOSEtoPKCS(COSEPublicKey);
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

      toReturn.verified = key.verify(signatureBaseHash, sig);
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

      toReturn.verified = key.verify(signatureBase, sig);
    } else if (kty === COSEKTY.OKP) {
      const x = cosePublicKey.get(COSEKEYS.x);

      if (!x) {
        throw new Error('COSE public key was missing x (Packed|OKP)');
      }

      const signatureBaseHash = toHash(signatureBase, hashAlg);

      const key = new elliptic.eddsa('ed25519');
      key.keyFromPublic(x as Buffer);

      // TODO: is `publicKey` right here?
      toReturn.verified = key.verify(signatureBaseHash, sig, publicKey);
    }
  }

  if (toReturn.verified) {
    toReturn.authenticatorInfo = {
      fmt,
      counter,
      base64PublicKey: base64url.encode(publicKey),
      base64CredentialID: base64url.encode(credentialID),
    };
  }

  return toReturn;
}

enum COSEKTY {
  OKP = 1,
  EC2 = 2,
  RSA = 3,
}

const COSERSASCHEME: { [key: string]: SigningSchemeHash } = {
  '-3': 'pss-sha256',
  '-39': 'pss-sha512',
  '-38': 'pss-sha384',
  '-65535': 'pkcs1-sha1',
  '-257': 'pkcs1-sha256',
  '-258': 'pkcs1-sha384',
  '-259': 'pkcs1-sha512',
};

const COSECRV: { [key: number]: string } = {
  1: 'p256',
  2: 'p384',
  3: 'p521',
};

const COSEALGHASH: { [key: string]: string } = {
  '-257': 'sha256',
  '-258': 'sha384',
  '-259': 'sha512',
  '-65535': 'sha1',
  '-39': 'sha512',
  '-38': 'sha384',
  '-37': 'sha256',
  '-7': 'sha256',
  '-8': 'sha512',
  '-36': 'sha512',
};
