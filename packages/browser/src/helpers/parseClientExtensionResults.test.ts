import { parseClientExtensionResults } from './parseClientExtensionResults';
import { utf8StringToBuffer } from './utf8StringToBuffer';
import {
  AuthenticationExtensionsClientOutputsFuture,
  AuthenticationCredential
} from '@simplewebauthn/typescript-types';

jest.mock('../helpers/browserSupportsWebAuthn');

const mockAuthenticatorData = 'mockAuthenticatorData';
const mockClientDataJSON = 'mockClientDataJSON';
const mockSignature = 'mockSignature';
const mockUserHandle = 'mockUserHandle';

test('should return client extension results in JSON format', async () => {
  const credential: AuthenticationCredential = {
    id: 'foobar',
    rawId: utf8StringToBuffer('foobar'),
    response: {
      authenticatorData: Buffer.from(mockAuthenticatorData, 'ascii'),
      clientDataJSON: Buffer.from(mockClientDataJSON, 'ascii'),
      signature: Buffer.from(mockSignature, 'ascii'),
      userHandle: Buffer.from(mockUserHandle, 'ascii'),
    },
    getClientExtensionResults: (): AuthenticationExtensionsClientOutputsFuture => {
      return {
        devicePubKey: {
          authenticatorOutput: Buffer.from('a66364706b584da50102032620012158206c2411290f2f5dc0d590c25ed9f4b9645a94bb8ecba2377765b103dad5c99243225820c10b2ab6051e0610388d3f2d75a624b94454f4f51948b3dcc6f34b7518f2455263666d74646e6f6e65656e6f6e6365406573636f7065006661616775696450000000000000000000000000000000006761747453746d74a0', 'hex'),
          signature: Buffer.from('3045022078ac013e33175eb74f335374715b70010f0fbef2a6697ce9402ec2a7485b7b45022100ca763fe60a93e03041df55c7020221d7c621849f8196126845d6d251e3bfd6b2', 'hex')
        }
      };
    },
    type: 'webauthn.create',
  };

  const result = parseClientExtensionResults(credential);

  expect(result).toMatchObject({
    devicePubKey: {
      authenticatorOutput: 'pmNkcGtYTaUBAgMmIAEhWCBsJBEpDy9dwNWQwl7Z9LlkWpS7jsuiN3dlsQPa1cmSQyJYIMELKrYFHgYQOI0_LXWmJLlEVPT1GUiz3MbzS3UY8kVSY2ZtdGRub25lZW5vbmNlQGVzY29wZQBmYWFndWlkUAAAAAAAAAAAAAAAAAAAAABnYXR0U3RtdKA',
      signature: 'MEUCIHisAT4zF163TzNTdHFbcAEPD77ypml86UAuwqdIW3tFAiEAynY_5gqT4DBB31XHAgIh18YhhJ-BlhJoRdbSUeO_1rI'
    }
  });
});
