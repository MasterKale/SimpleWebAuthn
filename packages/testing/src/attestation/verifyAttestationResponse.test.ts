import { verifyAttestationResponse } from '@simplewebauthn/server';

import GenerateAttestationOptionsTestingData from './generateAttestationOptions';
import VerifyAttestationResponseTestingData from './verifyAttestationResponse';

it('should return valid default data', async () => {
  const { options, result } = VerifyAttestationResponseTestingData.default();

  const expectedResult = await verifyAttestationResponse(options);

  expect(result).toEqual(expectedResult);
});

it('should return valid fidoU2F data', async () => {
  const { options, result } = VerifyAttestationResponseTestingData.fidoU2F();

  const expectedResult = await verifyAttestationResponse(options);

  expect(result).toEqual(expectedResult);
});

it('should return valid packed data', async () => {
  const { options, result } = VerifyAttestationResponseTestingData.packed();

  const expectedResult = await verifyAttestationResponse(options);

  expect(result).toEqual(expectedResult);
});

it('should return valid packedX5 data', async () => {
  const { options, result } = VerifyAttestationResponseTestingData.packedX5();

  const expectedResult = await verifyAttestationResponse(options);

  expect(result).toEqual(expectedResult);
});

it('should return valid none data', async () => {
  const { options, result } = VerifyAttestationResponseTestingData.none();

  const expectedResult = await verifyAttestationResponse(options);

  expect(result).toEqual(expectedResult);
});

it('should have consistent data across utils', () => {
  const { options } = VerifyAttestationResponseTestingData.default();
  const { result } = GenerateAttestationOptionsTestingData.default();

  expect(options.expectedRPID).toEqual(result.rp.id);
  expect(options.expectedOrigin).toContain(result.rp.id);
});
