import { COSEPublicKey } from "./cose.ts";
import { isoCBOR } from "./iso/index.ts";

export function decodeCredentialPublicKey(
  publicKey: Uint8Array,
): COSEPublicKey {
  return isoCBOR.decodeFirst<COSEPublicKey>(publicKey);
}
