import { parseBackupFlags } from './parseBackupFlags';

test('should return single-device cred, not backed up', () => {
  const parsed = parseBackupFlags({ be: false, bs: false });

  expect(parsed.credentialDeviceType).toEqual('singleDevice');
  expect(parsed.credentialBackedUp).toEqual(false);
});

test('should throw on single-device cred, backed up', () => {
  expect.assertions(2);

  try {
    parseBackupFlags({ be: false, bs: true });
  } catch (err) {
    const _err: Error = err as Error;
    expect(_err.message).toContain('impossible');
    expect(_err.name).toEqual('InvalidBackupFlags');
  }
});

test('should return multi-device cred, not backed up', () => {
  const parsed = parseBackupFlags({ be: true, bs: false });

  expect(parsed.credentialDeviceType).toEqual('multiDevice');
  expect(parsed.credentialBackedUp).toEqual(false);
});

test('should return multi-device cred, backed up', () => {
  const parsed = parseBackupFlags({ be: true, bs: true });

  expect(parsed.credentialDeviceType).toEqual('multiDevice');
  expect(parsed.credentialBackedUp).toEqual(true);
});
