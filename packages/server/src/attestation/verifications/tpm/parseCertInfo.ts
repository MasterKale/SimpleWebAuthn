import { TPM_ALG } from './constants';

export default function parseCertInfo(certInfo: Buffer): ParsedCertInfo {
  let certBuffer = certInfo;

  // Get a magic constant
  const magic = certBuffer.slice(0, 4).readUInt32BE(0);
  certBuffer = certBuffer.slice(4);

  // Determine the algorithm used for attestation
  const typeBuffer = certBuffer.slice(0, 2);
  certBuffer = certBuffer.slice(2);
  const type = TPM_ST[typeBuffer.readUInt16BE(0)];

  // The name of a parent entity, can be ignored
  const qualifiedSignerLength = certBuffer.slice(0, 2).readUInt16BE(0);
  certBuffer = certBuffer.slice(2);
  const qualifiedSigner = certBuffer.slice(0, qualifiedSignerLength);
  certBuffer = certBuffer.slice(qualifiedSignerLength);

  // Get the expected hash of `attsToBeSigned`
  const extraDataLength = certBuffer.slice(0, 2).readUInt16BE(0);
  certBuffer = certBuffer.slice(2);
  const extraData = certBuffer.slice(0, extraDataLength);
  certBuffer = certBuffer.slice(extraDataLength);

  // Information about the TPM device's internal clock, can be ignored
  const clockInfoBuffer = certBuffer.slice(0, 17);
  certBuffer = certBuffer.slice(17);
  const clockInfo = {
    clock: clockInfoBuffer.slice(0, 8),
    resetCount: clockInfoBuffer.slice(8, 12).readUInt32BE(0),
    restartCount: clockInfoBuffer.slice(12, 16).readUInt32BE(0),
    safe: !!clockInfoBuffer[16],
  };

  // TPM device firmware version
  const firmwareVersion = certBuffer.slice(0, 8);
  certBuffer = certBuffer.slice(8);

  // Attested Name
  const attestedNameLength = certBuffer.slice(0, 2).readUInt16BE(0);
  certBuffer = certBuffer.slice(2);
  const attestedName = certBuffer.slice(0, attestedNameLength);
  certBuffer = certBuffer.slice(attestedNameLength);

  // Attested qualified name, can be ignored
  const qualifiedNameLength = certBuffer.slice(0, 2).readUInt16BE(0);
  certBuffer = certBuffer.slice(2);
  const qualifiedName = certBuffer.slice(0, qualifiedNameLength);
  certBuffer = certBuffer.slice(qualifiedNameLength);

  const attested = {
    nameAlg: TPM_ALG[attestedName.slice(0, 2).readUInt16BE(0)],
    name: attestedName,
    qualifiedName,
  };

  return {
    magic,
    type,
    qualifiedSigner,
    extraData,
    clockInfo,
    firmwareVersion,
    attested,
  };
}

type ParsedCertInfo = {
  magic: number;
  type: string;
  qualifiedSigner: Buffer;
  extraData: Buffer;
  clockInfo: {
    clock: Buffer;
    resetCount: number;
    restartCount: number;
    safe: boolean;
  };
  firmwareVersion: Buffer;
  attested: {
    nameAlg: string;
    name: Buffer;
    qualifiedName: Buffer;
  };
};

const TPM_ST: { [key: number]: string } = {
  0x00c4: 'TPM_ST_RSP_COMMAND',
  0x8000: 'TPM_ST_NULL',
  0x8001: 'TPM_ST_NO_SESSIONS',
  0x8002: 'TPM_ST_SESSIONS',
  0x8014: 'TPM_ST_ATTEST_NV',
  0x8015: 'TPM_ST_ATTEST_COMMAND_AUDIT',
  0x8016: 'TPM_ST_ATTEST_SESSION_AUDIT',
  0x8017: 'TPM_ST_ATTEST_CERTIFY',
  0x8018: 'TPM_ST_ATTEST_QUOTE',
  0x8019: 'TPM_ST_ATTEST_TIME',
  0x801a: 'TPM_ST_ATTEST_CREATION',
  0x8021: 'TPM_ST_CREATION',
  0x8022: 'TPM_ST_VERIFIED',
  0x8023: 'TPM_ST_AUTH_SECRET',
  0x8024: 'TPM_ST_HASHCHECK',
  0x8025: 'TPM_ST_AUTH_SIGNED',
  0x8029: 'TPM_ST_FU_MANIFEST',
};
