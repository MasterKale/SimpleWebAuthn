import base64url from "base64url";
import { toHash } from "../helpers/toHash";
import { verifySignature } from "../helpers/verifySignature";
import { convertPublicKeyToPEM } from "../helpers/convertPublicKeyToPEM";

export function verifyDevicePublicKey(
  credentialID: string,
  clientDataJSON: string,
  nonce: string,
  dpk: Buffer,
  signature: Buffer,
): boolean {
  const _credentialID = base64url.toBuffer(credentialID);
  const clientDataHash = toHash(base64url.toBuffer(clientDataJSON));
  const _nonce = base64url.toBuffer(nonce);
  const signatureBase = Buffer.concat([_credentialID, clientDataHash, _nonce]);
  const publicKey = convertPublicKeyToPEM(dpk);

  return verifySignature(signature, signatureBase, publicKey);
}
