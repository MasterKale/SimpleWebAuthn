import { generateAttestationOptions } from '@simplewebauthn/server';
import GenerateAttestationOptionsTestingData from './generateAttestationOptions';

it('should return valid default data', () => {
  const { options, result } = GenerateAttestationOptionsTestingData.default();

  const expectedResult = generateAttestationOptions(options);

  expect(result).toEqual(expectedResult);
});
