import { isoCBOR } from './iso';

import { convertCOSEtoPKCS } from './convertCOSEtoPKCS';
import { COSEKEYS } from './cose';

test('should throw an error curve if, somehow, curve coordinate x is missing', () => {
  const mockCOSEKey = new Map<number, number | Buffer>();

  mockCOSEKey.set(COSEKEYS.y, 1);

  jest.spyOn(isoCBOR, 'decodeFirst').mockReturnValue(mockCOSEKey);

  expect(() => {
    convertCOSEtoPKCS(Buffer.from('123', 'ascii'));
  }).toThrow();
});

test('should throw an error curve if, somehow, curve coordinate y is missing', () => {
  const mockCOSEKey = new Map<number, number | Buffer>();

  mockCOSEKey.set(COSEKEYS.x, 1);

  jest.spyOn(isoCBOR, 'decodeFirst').mockReturnValue(mockCOSEKey);

  expect(() => {
    convertCOSEtoPKCS(Buffer.from('123', 'ascii'));
  }).toThrow();
});
