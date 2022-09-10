import { AuthenticationExtensionsDevicePublicKeyOutputs, AuthenticationExtensionsDevicePublicKeyOutputsJSON } from "@simplewebauthn/typescript-types";
import { decodeDevicePubKey, decodeDevicePubKeyAuthenticatorOutput } from "./decodeDevicePubKey";

it("should decode device public key client extension output", () => {
  const devicePubKeyJSON: AuthenticationExtensionsDevicePublicKeyOutputsJSON = {
    authenticatorOutput: 'pmNkcGtYTaUBAgMmIAEhWCBNwZidDC8QQNAffsFaxUKxTbVLxepdV-1_azg-u0-rsCJYIFtht9l1L8g2hqQOo8omnBd9fRj2byJzn1JQqnp19oVbY2ZtdGRub25lZW5vbmNlQGVzY29wZQBmYWFndWlkUAAAAAAAAAAAAAAAAAAAAABnYXR0U3RtdKA=',
    signature: 'MEUCIQDTf2ImngEOi3qHws6gxf6CpquI97oDIl8m_4T2xQO-YwIgdWN7elqNuU-yMZtGpy8hQtL_E-qmZ1_rM2u2nhXYw7A=',
  }

  const result = decodeDevicePubKey(devicePubKeyJSON);
  expect(result).toMatchObject({
    authenticatorOutput: Buffer.from('A66364706B584DA50102032620012158204DC1989D0C2F1040D01F7EC15AC542B14DB54BC5EA5D57ED7F6B383EBB4FABB02258205B61B7D9752FC83686A40EA3CA269C177D7D18F66F22739F5250AA7A75F6855B63666D74646E6F6E65656E6F6E6365406573636F7065006661616775696450000000000000000000000000000000006761747453746D74A0', 'hex'),
    signature: Buffer.from('3045022100d37f62269e010e8b7a87c2cea0c5fe82a6ab88f7ba03225f26ff84f6c503be63022075637b7a5a8db94fb2319b46a72f2142d2ff13eaa6675feb336bb69e15d8c3b0', 'hex'),
  });
});

it("should decode device public key authenticator output", () => {
  const devicePubKey: AuthenticationExtensionsDevicePublicKeyOutputs = {
    authenticatorOutput: Buffer.from('A66364706B584DA50102032620012158204DC1989D0C2F1040D01F7EC15AC542B14DB54BC5EA5D57ED7F6B383EBB4FABB02258205B61B7D9752FC83686A40EA3CA269C177D7D18F66F22739F5250AA7A75F6855B63666D74646E6F6E65656E6F6E6365406573636F7065006661616775696450000000000000000000000000000000006761747453746D74A0', 'hex'),
    signature: Buffer.from('3045022100d37f62269e010e8b7a87c2cea0c5fe82a6ab88f7ba03225f26ff84f6c503be63022075637b7a5a8db94fb2319b46a72f2142d2ff13eaa6675feb336bb69e15d8c3b0', 'hex'),
  }

  const result = decodeDevicePubKeyAuthenticatorOutput(devicePubKey.authenticatorOutput);
  expect(result).toMatchObject({
    dpk: Buffer.from('A50102032620012158204DC1989D0C2F1040D01F7EC15AC542B14DB54BC5EA5D57ED7F6B383EBB4FABB02258205B61B7D9752FC83686A40EA3CA269C177D7D18F66F22739F5250AA7A75F6855B', 'hex'),
    fmt: "none",
    nonce: Buffer.from('', 'hex'),
    scope: 0,
    aaguid: Buffer.from('00000000000000000000000000000000', 'hex'),
    attStmt: {},
  });
})
