import { verifyDpkSignature } from './devicePubKey';

it('should verify a device public key extension', async () => {
  const credentialID = 'cxjDB1h5nG6jpQW3EeeZNA';
  const clientDataJSON = 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoicTh1SVR0d0czMkhUU3RmdlVxVTcwWXNGNFJfS1A4WnZEYkVESVpZekNDdyIsIm9yaWdpbiI6ImFuZHJvaWQ6YXBrLWtleS1oYXNoOmd4N3NxX3B4aHhocklRZEx5ZkcwcHhLd2lKN2hPazJESlE0eHZLZDQzOFEiLCJhbmRyb2lkUGFja2FnZU5hbWUiOiJjb20uZmlkby5leGFtcGxlLmZpZG8yYXBpZXhhbXBsZSJ9';
  const devicePubKey = {
    aaguid: Buffer.from('B93FD961F2E6462FB12282002247DE78', 'hex'),
    dpk: Buffer.from('A5010203262001215820EDEAD3FD35769C23D340DDC1830A7FF20E7355F29D1C75AA0DC2B6AC182EA7D32258203451DC9992AF946825B441945FC9D134E17B73AA5FEA9580351E7C93F5D36513', 'hex'),
    sig: Buffer.from('3045022100BC6DD9AF5E47BB3AB82731299EAE82A779189E4E416E3A0E37A3BA64C38F991202205671EFAC0E8CD6DE1D3640CE7E4E89D3A97E0517B603D8AC28F23E4E1F74E639', 'hex'),
    nonce: Buffer.from('', 'hex'),
    scope: Buffer.from('00', 'hex')
  }
  const signature = devicePubKey.sig;
  
  const result = await verifyDpkSignature(credentialID, clientDataJSON, devicePubKey, signature);
  expect(result).toEqual(true);
});
