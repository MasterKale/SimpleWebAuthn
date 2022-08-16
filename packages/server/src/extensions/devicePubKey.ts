import base64url from "base64url";
import { convertPublicKeyToPEM } from "../helpers/convertPublicKeyToPEM";
import { toHash } from "../helpers/toHash";
import { verifySignature } from "../helpers/verifySignature";

export function verifyDevicePublicKey(
  clientDataJSON: string,
  authDataBuffer: Buffer,
  publicKey: Buffer,
  encodedSignature: string,
): boolean {
  const clientDataHash = toHash(base64url.toBuffer(clientDataJSON));
  const signatureBase = Buffer.concat([authDataBuffer, clientDataHash]);

  const PEM = convertPublicKeyToPEM(publicKey);
  const signature = base64url.toBuffer(encodedSignature);

  return verifySignature(signature, signatureBase, PEM);
}
