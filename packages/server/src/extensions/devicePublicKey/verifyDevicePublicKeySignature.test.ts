import { AuthenticationCredentialJSON, RegistrationCredentialJSON } from '@simplewebauthn/typescript-types';
import { decodeDevicePubKey, decodeDevicePubKeyAuthenticatorOutput } from './decodeDevicePubKey';
import { verifyDevicePublicKeySignature, VerifyDevicePublicKeySignatureOpts } from './verifyDevicePublicKeySignature';

it("should verify a registration response's device public key signature", async () => {
  const credential: RegistrationCredentialJSON = {
    response: {
      clientDataJSON: 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiNkM0QUptNmJyTVJwSF9JZVhDVmtHTTUydnVwTy14Y1huNldlcWIyVjJtTSIsIm9yaWdpbiI6ImFuZHJvaWQ6YXBrLWtleS1oYXNoOmd4N3NxX3B4aHhocklRZEx5ZkcwcHhLd2lKN2hPazJESlE0eHZLZDQzOFEiLCJhbmRyb2lkUGFja2FnZU5hbWUiOiJjb20uZmlkby5leGFtcGxlLmZpZG8yYXBpZXhhbXBsZSJ9',
      attestationObject: 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkBMA11_MVj_ad52y40PupImIh1i3hUnUk6T9vqHNlqoxzE3QAAAAAAAAAAAAAAAAAAAAAAAAAAABAHFimPeuzlYZbxRWdeyYzOpQECAyYgASFYIPLEylOIRiI7z7q6zuYjWB9TcOj9yNwmawogQJ4ZKpNAIlggd9ZqIjd30p1tIU6A8ue5wEZl9q_AsKR_leaHFZ_bwWmhbGRldmljZVB1YktleViMpmNkcGtYTaUBAgMmIAEhWCBNwZidDC8QQNAffsFaxUKxTbVLxepdV-1_azg-u0-rsCJYIFtht9l1L8g2hqQOo8omnBd9fRj2byJzn1JQqnp19oVbY2ZtdGRub25lZW5vbmNlQGVzY29wZQBmYWFndWlkUAAAAAAAAAAAAAAAAAAAAABnYXR0U3RtdKA=',
    },
    id: 'BxYpj3rs5WGW8UVnXsmMzg',
    rawId: 'BxYpj3rs5WGW8UVnXsmMzg',
    type: 'public-key',
    transports: [],
    clientExtensionResults: {
      devicePubKey: {
        authenticatorOutput: 'pmNkcGtYTaUBAgMmIAEhWCBNwZidDC8QQNAffsFaxUKxTbVLxepdV-1_azg-u0-rsCJYIFtht9l1L8g2hqQOo8omnBd9fRj2byJzn1JQqnp19oVbY2ZtdGRub25lZW5vbmNlQGVzY29wZQBmYWFndWlkUAAAAAAAAAAAAAAAAAAAAABnYXR0U3RtdKA=',
        signature: 'MEUCIQDTf2ImngEOi3qHws6gxf6CpquI97oDIl8m_4T2xQO-YwIgdWN7elqNuU-yMZtGpy8hQtL_E-qmZ1_rM2u2nhXYw7A=',
      }
    }
  };

  if (!credential.clientExtensionResults.devicePubKey) {
    throw new Error('This exception will not happen.');
  }

  const devicePubKey =  decodeDevicePubKey(credential.clientExtensionResults.devicePubKey);
  const { authenticatorOutput: encodedAuthenticatorOutput, signature } = devicePubKey;
  const dpkAuthOutput = decodeDevicePubKeyAuthenticatorOutput(encodedAuthenticatorOutput);

  const dpkOpts: VerifyDevicePublicKeySignatureOpts = {
    credential,
    authenticatorOutput: dpkAuthOutput,
    signature,
  }
  const result = await verifyDevicePublicKeySignature(dpkOpts);
  expect(result).toEqual(true);
});

it("should verify an authentication response's device public key signature", async () => {
  const credential: AuthenticationCredentialJSON = {
    response: {
      clientDataJSON: 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiS05aUmtPRU5KY1dCTzZHX0VjcE1GS2FWRDlham1xNExsZDZJMllJc1c3QSIsIm9yaWdpbiI6ImFuZHJvaWQ6YXBrLWtleS1oYXNoOmd4N3NxX3B4aHhocklRZEx5ZkcwcHhLd2lKN2hPazJESlE0eHZLZDQzOFEiLCJhbmRyb2lkUGFja2FnZU5hbWUiOiJjb20uZmlkby5leGFtcGxlLmZpZG8yYXBpZXhhbXBsZSJ9',
      authenticatorData: 'DXX8xWP9p3nbLjQ-6kiYiHWLeFSdSTpP2-oc2WqjHMSdAAAAAKFsZGV2aWNlUHViS2V5WIymY2Rwa1hNpQECAyYgASFYIE3BmJ0MLxBA0B9-wVrFQrFNtUvF6l1X7X9rOD67T6uwIlggW2G32XUvyDaGpA6jyiacF319GPZvInOfUlCqenX2hVtjZm10ZG5vbmVlbm9uY2VAZXNjb3BlAGZhYWd1aWRQAAAAAAAAAAAAAAAAAAAAAGdhdHRTdG10oA==',
      signature: 'MEUCIF1LvdGHiW5aq25ZrNVUeZOm7pcS_9a172pkO2C6ILE1AiEA8NYg-ZzOgt1pN0Bqv02t7lWCSMn_IPpvKHdT5Mjv75E=, userHandle=b2FPajFxcmM4MWo3QkFFel9RN2lEakh5RVNlU2RLNDF0Sl92eHpQYWV5UQ==',
      userHandle: 'b2FPajFxcmM4MWo3QkFFel9RN2lEakh5RVNlU2RLNDF0Sl92eHpQYWV5UQ==',
    },
    id: 'BxYpj3rs5WGW8UVnXsmMzg',
    rawId: 'BxYpj3rs5WGW8UVnXsmMzg',
    type: 'public-key',
    clientExtensionResults: {
      devicePubKey: {
        'authenticatorOutput': 'pmNkcGtYTaUBAgMmIAEhWCBNwZidDC8QQNAffsFaxUKxTbVLxepdV-1_azg-u0-rsCJYIFtht9l1L8g2hqQOo8omnBd9fRj2byJzn1JQqnp19oVbY2ZtdGRub25lZW5vbmNlQGVzY29wZQBmYWFndWlkUAAAAAAAAAAAAAAAAAAAAABnYXR0U3RtdKA=',
        'signature': 'MEQCIAdwrIjLt7ULTU5OzpnhzvbWJ3srVLoOCYs72Hlw6ugoAiAFl4_jfJJv89cM5qSx8lI_pIXLRIy6lO9N3O8SUjyNKQ==',
      }
    }
  };

  if (!credential.clientExtensionResults.devicePubKey) {
    throw new Error('This exception will not happen.');
  }

  const devicePubKey =  decodeDevicePubKey(credential.clientExtensionResults.devicePubKey);
  const {authenticatorOutput: encodedAuthenticatorOutput, signature } = devicePubKey;
  const dpkAuthOutput = decodeDevicePubKeyAuthenticatorOutput(encodedAuthenticatorOutput);

  const dpkOpts: VerifyDevicePublicKeySignatureOpts = {
    credential,
    authenticatorOutput: dpkAuthOutput,
    signature,
  }
  const result = await verifyDevicePublicKeySignature(dpkOpts);
  expect(result).toEqual(true);
});
