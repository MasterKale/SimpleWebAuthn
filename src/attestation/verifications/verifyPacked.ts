import base64url from 'base64url';
import cbor from 'cbor';
import elliptic from 'elliptic';
import NodeRSA, { SigningSchemeHash } from 'node-rsa';

import { AttestationObject, VerifiedAttestation, COSEKEYS, COSEPublicKey } from "@types";
import convertCOSEtoPKCS from "@helpers/convertCOSEtoPKCS";
import toHash from "@helpers/toHash";
import convertASN1toPEM from '@helpers/convertASN1toPEM';
import getCertificateInfo from '@helpers/getCertificateInfo';
import verifySignature from '@helpers/verifySignature';

import parseAttestationAuthData from '../parseAttestationAuthData';


/**
 * Verify an attestation response with fmt 'packed'
 */
export default function verifyAttestationPacked(attestationObject: AttestationObject,
  base64ClientDataJSON: string,
): VerifiedAttestation {
  const { fmt, authData, attStmt } = attestationObject;
  const { sig, x5c, ecdaaKeyId } = attStmt;

  const authDataStruct = parseAttestationAuthData(authData);

  const { COSEPublicKey, counter, credentialID } = authDataStruct;

  if (!COSEPublicKey) {
    throw new Error('No public key was provided by authenticator');
  }

  if (!credentialID) {
    throw new Error('No credential ID was provided by authenticator');
  }

  if (!sig) {
    throw new Error('No attestation signature provided in attestation statement');
  }

  const clientDataHash = toHash(base64url.toBuffer(base64ClientDataJSON));

  const signatureBase = Buffer.concat([
    authData,
    clientDataHash,
  ]);

  const toReturn: VerifiedAttestation = { verified: false };
  const publicKey = convertCOSEtoPKCS(COSEPublicKey);

  if (x5c) {
    console.log('FULL Attestation');

    const leafCert = convertASN1toPEM(x5c[0]);
    const leafCertInfo = getCertificateInfo(leafCert);

    const { subject, basicConstraintsCA, version } = leafCertInfo;
    const {
      OU,
      CN,
      O,
      C,
    } = subject;

    if (OU !== 'Authenticator Attestation') {
      throw new Error('Batch certificate OU MUST be set strictly to "Authenticator Attestation"!');
    }

    if (!CN) {
      throw new Error('Batch certificate CN MUST no be empty!');
    }

    if (!O) {
      throw new Error('Batch certificate CN MUST no be empty!');
    }

    if (!C || C.length !== 2) {
      throw new Error('Batch certificate C MUST be set to two character ISO 3166 code!');
    }

    if (basicConstraintsCA) {
      throw new Error('Batch certificate basic constraints CA MUST be false!');
    }

    if (version !== 3) {
      throw new Error('Batch certificate version MUST be 3(ASN1 2)!');
    }

    toReturn.verified = verifySignature(sig, signatureBase, leafCert);
  } else if (ecdaaKeyId) {
    throw new Error('ECDAA not supported yet');
  } else {
    console.log('SELF Attestation');

    const cosePublicKey: COSEPublicKey = cbor.decodeAllSync(COSEPublicKey)[0];

    const kty = cosePublicKey.get(COSEKEYS.kty);
    const alg = cosePublicKey.get(COSEKEYS.alg);

    if (!alg) {
      throw new Error('COSE public key was missing alg');
    }

    if (!kty) {
      throw new Error('COSE public key was missing kty');
    }

    const hashAlg: string = COSEALGHASH[(alg as number)];

    if (kty === COSEKTY.EC2) {
      console.log('EC2');

      const crv = cosePublicKey.get(COSEKEYS.crv);

      if (!crv) {
        throw new Error('COSE public key was missing kty crv');
      }

      const pkcsPublicKey = convertCOSEtoPKCS(cosePublicKey);
      const signatureBaseHash = toHash(signatureBase, hashAlg);

      const ec = new elliptic.ec(COSECRV[(crv as number)]);
      const key = ec.keyFromPublic(pkcsPublicKey);

      toReturn.verified = key.verify(signatureBaseHash, sig);
    } else if (kty === COSEKTY.RSA) {
      console.log('RSA');

      const n = cosePublicKey.get(COSEKEYS.n);

      if (!n) {
        throw new Error('COSE public key was missing n');
      }

      const signingScheme = COSERSASCHEME[alg as number];

      // TODO: Verify this works
      const key = new NodeRSA();
      key.setOptions({ signingScheme });
      key.importKey({
        n: (n as Buffer),
        e: 65537,
      }, 'components-public');

      toReturn.verified = key.verify(signatureBase, sig);
    } else if (kty === COSEKTY.OKP) {
      console.log('OKP');

      const x = cosePublicKey.get(COSEKEYS.x);

      if (!x) {
        throw new Error('COSE public key was missing x');
      }

      const signatureBaseHash = toHash(signatureBase, hashAlg);

      const key = new elliptic.eddsa('ed25519');
      key.keyFromPublic((x as Buffer));

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
  '-259': 'pkcs1-sha512'
}

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
  '-36': 'sha512'
}
