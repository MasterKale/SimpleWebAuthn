import { type ManufacturerInfo, TPM_MANUFACTURERS } from './constants.ts';

export function getTPMManufacturerInfo(id: string): ManufacturerInfo | undefined {
  // e.g. "id:51434f4d" -> "id:51434f4D"
  const _normalized = `id:${id.substring(3).toUpperCase()}`;

  return TPM_MANUFACTURERS[_normalized];
}
