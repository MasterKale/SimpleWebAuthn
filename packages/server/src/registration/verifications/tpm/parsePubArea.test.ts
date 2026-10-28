import { assert, assertEquals } from '@std/assert';

import { parsePubArea } from './parsePubArea.ts';
import { isoUint8Array } from '../../../helpers/index.ts';

Deno.test('should parse details in ECC parameters', () => {
  const parsed = parsePubArea(
    isoUint8Array.fromHex(
      '0023000b00060472000000100018000b000300100020d1f49484ed2dfcfbe4b532341570d7198551d05f18ff4598b22be90299007e430020b397386c12c4f8d8f904925428dcbcbc6cd9448bf19a0a730d2339466135b4d7',
    ),
  );

  assertEquals(parsed.type, 'TPM_ALG_ECC');
  assertEquals(parsed.nameAlg, 'TPM_ALG_SHA256');
  assertEquals(parsed.parameters.ecc?.symmetric, 'TPM_ALG_NULL');
  assertEquals(parsed.parameters.ecc?.scheme, 'TPM_ALG_ECDSA');
  assertEquals(parsed.parameters.ecc?.details, { hashAlg: 'TPM_ALG_SHA256' });
  assertEquals(parsed.parameters.ecc?.curveID, 'TPM_ECC_NIST_P256');
  assertEquals(parsed.parameters.ecc?.kdf, 'TPM_ALG_NULL');
  assert(
    isoUint8Array.areEqual(
      parsed.unique,
      isoUint8Array.concat([
        isoUint8Array.fromHex('d1f49484ed2dfcfbe4b532341570d7198551d05f18ff4598b22be90299007e43'),
        isoUint8Array.fromHex('b397386c12c4f8d8f904925428dcbcbc6cd9448bf19a0a730d2339466135b4d7'),
      ]),
    ),
    'pubArea.unique was not expected x|y',
  );
});
