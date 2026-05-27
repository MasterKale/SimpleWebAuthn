import { assert } from '@std/assert';

import { BaseMetadataService } from './metadataService.ts';

/**
 * This is a very expensive test to run as it involves live network traffic on each run, and can
 * fail CI when MDS is having a bad day. I'm going to ignore it for now but keep it around as a
 * good end-to-end test to have on-hand to run locally.
 */
Deno.test('should be able to load from FIDO MDS and get statement for YubiKey 5', { ignore: true }, async () => {
  const service = new BaseMetadataService();

  await service.initialize();

  /**
   * From Yubico's list of AAGUIDs
   *
   * See https://support.yubico.com/hc/en-us/articles/360016648959-YubiKey-Hardware-FIDO2-AAGUIDs
   */
  const aaguidYubiKey5 = 'ee882879-721c-4913-9775-3dfcce97072a';
  const statement = await service.getStatement(aaguidYubiKey5);

  assert(statement);
});
