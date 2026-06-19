import { assertEquals } from '@std/assert';
import { getTPMManufacturerInfo } from './isValidTPMManufacturerID.ts';

Deno.test('should normalize manufacturer ID - Qualcomm', () => {
  const isValid = getTPMManufacturerInfo('id:51434f4d');

  assertEquals(isValid?.id, 'QCOM');
  assertEquals(isValid?.name, 'Qualcomm');
});

Deno.test('should normalize manufacturer ID - IBM', () => {
  const isValid = getTPMManufacturerInfo('id:49424d00');

  assertEquals(isValid?.id, 'IBM');
  assertEquals(isValid?.name, 'IBM');
});

Deno.test('should return undefined for bad manufacturer ID', () => {
  const isValid = getTPMManufacturerInfo('');

  assertEquals(isValid, undefined);
});
