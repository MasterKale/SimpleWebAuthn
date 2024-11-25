import { assertThrows } from '@std/assert';

import { isoCBOR } from './iso/index.ts';

import { convertCOSEtoPKCS } from './convertCOSEtoPKCS.ts';
import { COSEKEYS } from './cose.ts';

Deno.test('should throw an error curve if, somehow, curve coordinate x is missing', () => {
  const mockCOSEKey = new Map<number, number | Uint8Array>();
  mockCOSEKey.set(COSEKEYS.y, 1);

  const badPublicKey = isoCBOR.encode(mockCOSEKey);

  assertThrows(
    () => convertCOSEtoPKCS(badPublicKey),
    Error,
    'public key was missing x',
  );
});
