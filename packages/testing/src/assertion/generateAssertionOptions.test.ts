import { generateAssertionOptions } from '@simplewebauthn/server';
import GenerateAssertionOptionsTestingData from './generateAssertionOptions';

it('should return valid default data', () => {
  const { options, result } = GenerateAssertionOptionsTestingData.default();

  const expectedResult = generateAssertionOptions(options);

  expect(result).toEqual(expectedResult);
});

it('should return valid data with allow credentials', () => {
  const { options, result } = GenerateAssertionOptionsTestingData.withAllowCredentials();

  const expectedResult = generateAssertionOptions(options);

  expect(result).toEqual(expectedResult);
});
