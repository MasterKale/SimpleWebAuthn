import { assert } from 'https://deno.land/std@0.198.0/assert/mod.ts';

import { COSEALG, COSECRV, COSEKEYS, COSEKTY, COSEPublicKeyEC2 } from '../../cose.ts';
import { verifyEC2 } from './verifyEC2.ts';
import { unwrapEC2Signature } from './unwrapEC2Signature.ts';
import { isoBase64URL } from '../index.ts';

Deno.test(
  'should verify a signature signed with an P-256 public key',
  async () => {
    const cosePublicKey: COSEPublicKeyEC2 = new Map();
    cosePublicKey.set(COSEKEYS.kty, COSEKTY.EC2);
    cosePublicKey.set(COSEKEYS.alg, COSEALG.ES256);
    cosePublicKey.set(COSEKEYS.crv, COSECRV.P256);
    cosePublicKey.set(
      COSEKEYS.x,
      isoBase64URL.toBuffer('_qRi-kwOVobsqJ_1GAHZYfC77QoIdsVFYkx2Mw20UM4'),
    );
    cosePublicKey.set(
      COSEKEYS.y,
      isoBase64URL.toBuffer('BXEathwyOK_uQRmlZ_m4wReHLujSXk_-e3-9co5B2MY'),
    );

    const data = isoBase64URL.toBuffer('Bt81jmu3ieajF4w1at8HmieVOTDymHd7xJguJCUsL-Q');
    const signature = isoBase64URL.toBuffer(
      'MEQCH1h_F7TPTMVh_kwb_ssjD0_2U77bbXazz2ux-P6khLQCIQCutHs9eCBkCIMP3yA9mmNRKEfFd-REmhGY2GbHozaC7w'
    );

    const verified = await verifyEC2({
      cosePublicKey,
      data,
      signature: unwrapEC2Signature(signature, COSECRV.P256),
    });

    assert(verified);
  },
);

Deno.test(
  'should verify a signature signed with an P-384 public key',
  async () => {
    const cosePublicKey: COSEPublicKeyEC2 = new Map();
    cosePublicKey.set(COSEKEYS.kty, COSEKTY.EC2);
    cosePublicKey.set(COSEKEYS.alg, COSEALG.ES384);
    cosePublicKey.set(COSEKEYS.crv, COSECRV.P384);
    cosePublicKey.set(
      COSEKEYS.x,
      isoBase64URL.toBuffer('pm-0exykk1x0O72S9sm6fl-iXxFrGikjQHi1CgONIiEz_yDJdCPxN453qg6HLkOx'),
    );
    cosePublicKey.set(
      COSEKEYS.y,
      isoBase64URL.toBuffer('2B7yW7sgza8Sf7ifznQlGJqmJxgupkAevUqqOJTWaWBZiQ7sAf-TfAaNBukiz12K'),
    );

    const data = isoBase64URL.toBuffer('D7mI8UwWXv4rpfSQUNqtUXAhZEPbRLugmWclPpJ9m7c');
    const signature = isoBase64URL.toBuffer(
      'MGMCL3lZ2Rjxo5WcmTCdWyB6jTE9PVuduOR_AsJu956J9S_mFNbHP_-MbyWem4dfb5iqAjABJhTRltNl5Y0O4XC7YLNsYKq2WxYQ1HFOMGsr6oNkUPsX3UAr2zeeWL_Tp1VgHeM'
    );

    const verified = await verifyEC2({
      cosePublicKey,
      data,
      signature: unwrapEC2Signature(signature, COSECRV.P384),
    });

    assert(verified);
  },
);

Deno.test({
  // This test is currently ignored, as Deno's implementation of `WebCrypto.subtle` API does not
  // support the P-521 curve at the moment.
  ignore: true,
  name: 'should verify a signature signed with an P-521 public key',
  async fn() {
    const cosePublicKey: COSEPublicKeyEC2 = new Map();
    cosePublicKey.set(COSEKEYS.kty, COSEKTY.EC2);
    cosePublicKey.set(COSEKEYS.alg, COSEALG.ES512);
    cosePublicKey.set(COSEKEYS.crv, COSECRV.P521);
    cosePublicKey.set(
      COSEKEYS.x,
      isoBase64URL.toBuffer('AaLbnrCvCuQivbknRW50FjdqPQv4NRF9tHsN4QuVQ3sw8uSspd33o-NTBfjg5JzX9rnpbkKDigb6NugmrVjzNMNK'),
    );
    cosePublicKey.set(
      COSEKEYS.y,
      isoBase64URL.toBuffer('AE64axa8L8PkLX5Td0GaX79cLOW9E2-8-ObhL9XT_ih-1XxbGQcA5VhL1gI0xIQq5zYAxgZYey6PmbbqgtcUPRVt'),
    );

    const data = isoBase64URL.toBuffer('5p0h9RZTjLoBlnL2nY5pqOnhGy4q60NzbjDe2rVDR7o');
    const signature = isoBase64URL.toBuffer(
      'MIGHAkFRpbGknlgpETORypMprGBXMkJMfuqgJupy3NcgCOaJJdj3Voz74kV2pjPqkLNpuO9FqVtXeEsUw-jYsBHcMqHZhwJCAQ88uFDJS5g81XVBcLMIgf6ro-F-5jgRAmHx3CRVNGdk81MYbFJhT3hd2w9RdhT8qBG0zzRBXYAcHrKo0qJwQZot'
    );

    const verified = await verifyEC2({
      cosePublicKey,
      data,
      signature: unwrapEC2Signature(signature, COSECRV.P521),
    });

    assert(verified);
  },
});
