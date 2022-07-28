import { convertAAGUIDToString } from './convertAAGUIDToString';

test('should convert buffer to UUID string', () => {
  const uuid = convertAAGUIDToString(Buffer.from('adce000235bcc60a648b0b25f1f05503', 'hex'));

  expect(uuid).toEqual('adce0002-35bc-c60a-648b-0b25f1f05503');
});
