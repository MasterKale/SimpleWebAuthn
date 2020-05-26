import base64js from 'base64-js';
import type { PublicKeyCredentialDescriptorJSON } from '@webauthntine/typescript-types';

export default function toPublicKeyCredentialDescriptor(
  descriptor: PublicKeyCredentialDescriptorJSON,
): PublicKeyCredentialDescriptor {
  // Make sure the Base64'd credential ID length is a multiple of 4 or else toByteArray will throw
  const { id } = descriptor;
  const padLength = 4 - (id.length % 4);
  const paddedId = id.padEnd(id.length + padLength, '=');

  return {
    ...descriptor,
    id: base64js.toByteArray(paddedId),
  };
}
