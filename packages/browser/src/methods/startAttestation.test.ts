import type { AttestationCredential, PublicKeyCredentialCreationOptionsJSON } from '@webauthntine/typescript-types';
import base64js from 'base64-js';
import toUint8Array from '../helpers/toUint8Array';
import supportsWebauthn from '../helpers/supportsWebauthn';
import startAttestation from './startAttestation';

jest.mock('../helpers/supportsWebauthn');

const mockNavigatorCreate = (window.navigator.credentials.create as jest.Mock);
const mockSupportsWebauthn = (supportsWebauthn as jest.Mock);

const mockAttestationObject = 'mockAtte';
const mockClientDataJSON = 'mockClie';

const goodOpts1: PublicKeyCredentialCreationOptionsJSON = {
  publicKey: {
    challenge: 'fizz',
    attestation: 'direct',
    pubKeyCredParams: [{
      alg: -7,
      type: "public-key",
    }],
    rp: {
      id: '1234',
      name: 'webauthntine',
    },
    user: {
      id: '5678',
      displayName: 'username',
      name: 'username',
    },
    timeout: 1,
  },
};

beforeEach(() => {
  mockNavigatorCreate.mockReset();
  mockSupportsWebauthn.mockReset();
});

test('should convert options before passing to navigator.credentials.create(...)', async (done) => {
  mockSupportsWebauthn.mockReturnValue(true);

  // Stub out a response so the method won't throw
  mockNavigatorCreate.mockImplementation((): Promise<any> => {
    return new Promise((resolve) => {
      resolve({ response: {} });
    });
  });

  await startAttestation(goodOpts1);

  const argsPublicKey = mockNavigatorCreate.mock.calls[0][0].publicKey;

  expect(argsPublicKey.challenge).toEqual(toUint8Array(goodOpts1.publicKey.challenge));
  expect(argsPublicKey.user.id).toEqual(toUint8Array(goodOpts1.publicKey.user.id));

  done();
});

test('should return base64-encoded response values', async (done) => {
  mockSupportsWebauthn.mockReturnValue(true);

  mockNavigatorCreate.mockImplementation((): Promise<AttestationCredential> => {
    return new Promise((resolve) => {
      resolve({
        id: 'foobar',
        rawId: toUint8Array('foobar'),
        response: {
          attestationObject: base64js.toByteArray(mockAttestationObject),
          clientDataJSON: base64js.toByteArray(mockClientDataJSON),
        },
        getClientExtensionResults: () => ({}),
        type: 'webauthn.create',
      });
    });
  });

  const response = await startAttestation(goodOpts1);

  expect(response).toEqual({
    base64AttestationObject: mockAttestationObject,
    base64ClientDataJSON: mockClientDataJSON,
  });

  done();
})

test('should throw error if WebAuthn isn\'t supported', async (done) => {
  mockSupportsWebauthn.mockReturnValue(false);

  await expect(startAttestation(goodOpts1)).rejects.toThrow('WebAuthn is not supported in this browser');

  done();
});

test('should throw error if attestation is cancelled for some reason', async (done) => {
  mockSupportsWebauthn.mockReturnValue(true);

  mockNavigatorCreate.mockImplementation((): Promise<null> => {
    return new Promise((resolve) => {
      resolve(null);
    });
  });

  await expect(startAttestation(goodOpts1)).rejects.toThrow('Attestation was not completed');

  done();
});
