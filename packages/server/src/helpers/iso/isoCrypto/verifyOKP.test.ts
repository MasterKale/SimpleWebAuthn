import { COSEALG, COSECRV, COSEKEYS, COSEKTY, COSEPublicKeyOKP } from '../../cose';
import { verifyOKP } from './verifyOKP';

test('should verify a signature signed with an Ed25519 public key', async () => {
  const cosePublicKey: COSEPublicKeyOKP = new Map();
  cosePublicKey.set(COSEKEYS.kty, COSEKTY.OKP);
  cosePublicKey.set(COSEKEYS.alg, COSEALG.EdDSA);
  cosePublicKey.set(COSEKEYS.crv, COSECRV.ED25519);
  cosePublicKey.set(
    COSEKEYS.x,
    new Uint8Array([
      108, 223, 182, 117, 49, 249, 221, 119, 212, 171, 158, 83, 213, 25, 47, 92, 202, 112, 29, 93,
      29, 69, 89, 204, 4, 252, 110, 56, 25, 181, 250, 242,
    ]),
  );

  const data = new Uint8Array([
    73, 150, 13, 229, 136, 14, 140, 104, 116, 52, 23, 15, 100, 118, 96, 91, 143, 228, 174, 185, 162,
    134, 50, 199, 153, 92, 243, 186, 131, 29, 151, 99, 65, 0, 0, 0, 50, 145, 223, 234, 215, 149,
    158, 68, 117, 173, 38, 155, 13, 72, 43, 224, 137, 0, 32, 26, 165, 170, 88, 196, 173, 98, 22, 89,
    49, 152, 159, 162, 234, 142, 198, 252, 167, 119, 99, 175, 187, 21, 101, 110, 214, 98, 129, 2,
    202, 30, 113, 164, 1, 1, 3, 39, 32, 6, 33, 88, 32, 108, 223, 182, 117, 49, 249, 221, 119, 212,
    171, 158, 83, 213, 25, 47, 92, 202, 112, 29, 93, 29, 69, 89, 204, 4, 252, 110, 56, 25, 181, 250,
    242, 180, 65, 206, 26, 160, 29, 17, 43, 138, 105, 200, 52, 116, 140, 10, 89, 241, 15, 241, 83,
    248, 162, 190, 130, 32, 220, 100, 15, 154, 150, 65, 140,
  ]);
  const signature = new Uint8Array([
    29, 218, 16, 150, 129, 34, 25, 37, 7, 127, 215, 73, 93, 181, 115, 201, 99, 91, 14, 29, 10, 219,
    155, 105, 53, 4, 41, 143, 152, 107, 146, 16, 156, 117, 252, 244, 164, 32, 79, 182, 160, 161,
    145, 175, 248, 145, 242, 27, 133, 254, 137, 201, 141, 68, 24, 11, 159, 246, 148, 29, 194, 162,
    85, 5,
  ]);

  const verified = await verifyOKP({
    cosePublicKey,
    data,
    signature,
  });

  expect(verified).toBe(true);
});
