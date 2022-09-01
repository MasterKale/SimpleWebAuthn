import { AuthenticationCredentialJSON, AuthenticatorAssertionResponseJSON, AuthenticatorAttestationResponseJSON, RegistrationCredentialJSON } from '@simplewebauthn/typescript-types';
import { verifyDevicePublicKeySignature } from './verifyDevicePublicKeySignature';

it("should verify a registration response's device public key signature", async () => {
  const credential: RegistrationCredentialJSON = {
    response: {
      clientDataJSON: 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiNFF3dmdUVjhlaTF5TzYyaDF2bVFNWFM2SDZ3UGc0YWt2eDNKcF9VakF3cyIsIm9yaWdpbiI6ImFuZHJvaWQ6YXBrLWtleS1oYXNoOmd4N3NxX3B4aHhocklRZEx5ZkcwcHhLd2lKN2hPazJESlE0eHZLZDQzOFEiLCJhbmRyb2lkUGFja2FnZU5hbWUiOiJjb20uZmlkby5leGFtcGxlLmZpZG8yYXBpZXhhbXBsZSJ9',
      attestationObject: 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkBaQ11_MVj_ad52y40PupImIh1i3hUnUk6T9vqHNlqoxzExQAAAAAAAAAAAAAAAAAAAAAAAAAAABBzGMMHWHmcbqOlBbcR55k0pQECAyYgASFYIIukb9t-EtGUOa2t6YiJEAgz7GyqBN4DFTCzkcMiUGqIIlggmm6GzBPSzP9IYJnX-89R_zmKl6-qQSeQ2qomEC6Cr32hbGRldmljZVB1YktleaVjZHBrWE2lAQIDJiABIVgg7erT_TV2nCPTQN3Bgwp_8g5zVfKdHHWqDcK2rBgup9MiWCA0UdyZkq-UaCW0QZRfydE04Xtzql_qlYA1HnyT9dNlE2NzaWdYRjBEAiALHwldj84eCsg9f0fHD9hylpUK8N_TGOBKBQPoNvfWjQIgChIUfdbO1HBavxbZGQxIt4v23FqFLB2nzwip-avJ6etlbm9uY2VAZXNjb3BlQQBmYWFndWlkUAAAAAAAAAAAAAAAAAAAAAA=',
    },
    id: 'cxjDB1h5nG6jpQW3EeeZNA',
    rawId: 'cxjDB1h5nG6jpQW3EeeZNA',
    type: 'public-key',
    transports: [],
    clientExtensionResults: {}
  };

  const devicePubKey = {
    aaguid: Buffer.from('00000000000000000000000000000000', 'hex'),
    dpk: Buffer.from('A5010203262001215820EDEAD3FD35769C23D340DDC1830A7FF20E7355F29D1C75AA0DC2B6AC182EA7D32258203451DC9992AF946825B441945FC9D134E17B73AA5FEA9580351E7C93F5D36513', 'hex'),
    sig: Buffer.from('304402200B1F095D8FCE1E0AC83D7F47C70FD87296950AF0DFD318E04A0503E836F7D68D02200A12147DD6CED4705ABF16D9190C48B78BF6DC5A852C1DA7CF08A9F9ABC9E9EB', 'hex'),
    nonce: Buffer.from('', 'hex'),
    scope: Buffer.from('00', 'hex')
  }
  const signature = devicePubKey.sig;
  
  const result = await verifyDevicePublicKeySignature({ credential, devicePubKey, signature });
  expect(result).toEqual(true);
});

it("should verify an authentication response's device public key signature", async () => {
  const credential = {
    response: {
      clientDataJSON: 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoicTh1SVR0d0czMkhUU3RmdlVxVTcwWXNGNFJfS1A4WnZEYkVESVpZekNDdyIsIm9yaWdpbiI6ImFuZHJvaWQ6YXBrLWtleS1oYXNoOmd4N3NxX3B4aHhocklRZEx5ZkcwcHhLd2lKN2hPazJESlE0eHZLZDQzOFEiLCJhbmRyb2lkUGFja2FnZU5hbWUiOiJjb20uZmlkby5leGFtcGxlLmZpZG8yYXBpZXhhbXBsZSJ9',
      authenticatorData: 'DXX8xWP9p3nbLjQ-6kiYiHWLeFSdSTpP2-oc2WqjHMSFAAAAAKFsZGV2aWNlUHViS2V5pWNkcGtYTaUBAgMmIAEhWCDt6tP9NXacI9NA3cGDCn_yDnNV8p0cdaoNwrasGC6n0yJYIDRR3JmSr5RoJbRBlF_J0TThe3OqX-qVgDUefJP102UTY3NpZ1hHMEUCIQC8bdmvXke7OrgnMSmeroKneRieTkFuOg43o7pkw4-ZEgIgVnHvrA6M1t4dNkDOfk6J06l-BRe2A9isKPI-Th905jllbm9uY2VAZXNjb3BlQQBmYWFndWlkULk_2WHy5kYvsSKCACJH3ng=',
      signature: 'MEUCIEXJbR9-0cpcUdGAJi25Qf3z22lnCidx3box2b0bWKhwAiEAkp5zCbVbN2CEtIyezQEa9SOG62xm8YHdE1G5qov64j8=',
      userHandle: 'b2FPajFxcmM4MWo3QkFFel9RN2lEakh5RVNlU2RLNDF0Sl92eHpQYWV5UQ==',
    },
    id: 'cxjDB1h5nG6jpQW3EeeZNA',
    rawId: 'cxjDB1h5nG6jpQW3EeeZNA',
    type: 'public-key',
  } as AuthenticationCredentialJSON;

  const devicePubKey = {
    aaguid: Buffer.from('B93FD961F2E6462FB12282002247DE78', 'hex'),
    dpk: Buffer.from('A5010203262001215820EDEAD3FD35769C23D340DDC1830A7FF20E7355F29D1C75AA0DC2B6AC182EA7D32258203451DC9992AF946825B441945FC9D134E17B73AA5FEA9580351E7C93F5D36513', 'hex'),
    sig: Buffer.from('3045022100BC6DD9AF5E47BB3AB82731299EAE82A779189E4E416E3A0E37A3BA64C38F991202205671EFAC0E8CD6DE1D3640CE7E4E89D3A97E0517B603D8AC28F23E4E1F74E639', 'hex'),
    nonce: Buffer.from('', 'hex'),
    scope: Buffer.from('00', 'hex')
  }
  const signature = devicePubKey.sig;
  
  const result = await verifyDevicePublicKeySignature({ credential, devicePubKey, signature });
  expect(result).toEqual(true);
});
