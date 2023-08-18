import { assert } from 'https://deno.land/std@0.198.0/assert/mod.ts';

import { BaseMetadataService } from './metadataService.ts';

Deno.test('should be able to load from FIDO MDS and get statement for YubiKey 5', async () => {
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
