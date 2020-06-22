import { TPM_ST, TPM_ALG } from './constants';

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
