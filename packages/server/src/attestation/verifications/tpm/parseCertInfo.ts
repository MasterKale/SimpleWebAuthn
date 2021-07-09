import { TPM_ST, TPM_ALG } from './constants';

/**
 * Cut up a TPM attestation's certInfo into intelligible chunks
 */
export default function parseCertInfo(certInfo: Buffer): ParsedCertInfo {
  let pointer = 0;

  // Get a magic constant
  const magic = certInfo.slice(pointer, (pointer += 4)).readUInt32BE(0);

  // Determine the algorithm used for attestation
  const typeBuffer = certInfo.slice(pointer, (pointer += 2));
  const type = TPM_ST[typeBuffer.readUInt16BE(0)];

  // The name of a parent entity, can be ignored
  const qualifiedSignerLength = certInfo.slice(pointer, (pointer += 2)).readUInt16BE(0);
  const qualifiedSigner = certInfo.slice(pointer, (pointer += qualifiedSignerLength));

  // Get the expected hash of `attsToBeSigned`
  const extraDataLength = certInfo.slice(pointer, (pointer += 2)).readUInt16BE(0);
  const extraData = certInfo.slice(pointer, (pointer += extraDataLength));

  // Information about the TPM device's internal clock, can be ignored
  const clockInfoBuffer = certInfo.slice(pointer, (pointer += 17));
  const clockInfo = {
    clock: clockInfoBuffer.slice(0, 8),
    resetCount: clockInfoBuffer.slice(8, 12).readUInt32BE(0),
    restartCount: clockInfoBuffer.slice(12, 16).readUInt32BE(0),
    safe: !!clockInfoBuffer[16],
  };

  // TPM device firmware version
  const firmwareVersion = certInfo.slice(pointer, (pointer += 8));

  // Attested Name
  const attestedNameLength = certInfo.slice(pointer, (pointer += 2)).readUInt16BE(0);
  const attestedName = certInfo.slice(pointer, (pointer += attestedNameLength));

  // Attested qualified name, can be ignored
  const qualifiedNameLength = certInfo.slice(pointer, (pointer += 2)).readUInt16BE(0);
  const qualifiedName = certInfo.slice(pointer, (pointer += qualifiedNameLength));

  const attested = {
    nameAlg: TPM_ALG[attestedName.slice(0, 2).readUInt16BE(0)],
    nameAlgBuffer: attestedName.slice(0, 2),
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
    nameAlgBuffer: Buffer;
    name: Buffer;
    qualifiedName: Buffer;
  };
};
