import type {
  AuthenticatorTransport,
  PublicKeyCredentialDescriptor,
  PublicKeyCredentialDescriptorJSON,
  PublicKeyCredentialType,
} from '../types/index.ts';
import { base64URLStringToBuffer } from './base64URLStringToBuffer.ts';

export function toPublicKeyCredentialDescriptor(
  descriptor: PublicKeyCredentialDescriptorJSON,
): PublicKeyCredentialDescriptor {
  const { id } = descriptor;

  return {
    ...descriptor,
    id: base64URLStringToBuffer(id),
    transports: descriptor.transports as AuthenticatorTransport[],
    type: descriptor.type as PublicKeyCredentialType,
  };
}
