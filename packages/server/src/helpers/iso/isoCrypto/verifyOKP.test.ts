import { assert } from '@std/assert';

import { COSEALG, COSECRV, COSEKEYS, COSEKTY, COSEPublicKeyOKP } from '../../cose.ts';
import { verifyOKP } from './verifyOKP.ts';
import { isoBase64URL } from '../index.ts';

Deno.test(
  'should verify a signature signed with an Ed25519 public key',
  async () => {
    const cosePublicKey: COSEPublicKeyOKP = new Map();
    cosePublicKey.set(COSEKEYS.kty, COSEKTY.OKP);
    cosePublicKey.set(COSEKEYS.alg, COSEALG.EdDSA);
    cosePublicKey.set(COSEKEYS.crv, COSECRV.ED25519);
    cosePublicKey.set(
      COSEKEYS.x,
      isoBase64URL.toBuffer('bN-2dTH53XfUq55T1RkvXMpwHV0dRVnMBPxuOBm1-vI'),
    );

    const data = isoBase64URL.toBuffer(
      'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAMpHf6teVnkR1rSabDUgr4IkAIBqlqljErWIWWTGYn6Lqjsb8p3djr7sVZW7WYoECyh5xpAEBAycgBiFYIGzftnUx-d131KueU9UZL1zKcB1dHUVZzAT8bjgZtfrytEHOGqAdESuKacg0dIwKWfEP8VP4or6CINxkD5qWQYw',
    );
    const signature = isoBase64URL.toBuffer(
      'HdoQloEiGSUHf9dJXbVzyWNbDh0K25tpNQQpj5hrkhCcdfz0pCBPtqChka_4kfIbhf6JyY1EGAuf9pQdwqJVBQ',
    );

    const verified = await verifyOKP({
      cosePublicKey,
      data,
      signature,
    });

    assert(verified);
  },
);
