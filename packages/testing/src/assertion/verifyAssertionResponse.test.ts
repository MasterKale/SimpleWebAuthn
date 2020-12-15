import { verifyAssertionResponse } from '@simplewebauthn/server';

import GenerateAssertionOptionsTestingData from './generateAssertionOptions';
import VerifyAssertionResponseTestingData from './verifyAssertionResponse';

it('should return valid default data', () => {
  const { options, result } = VerifyAssertionResponseTestingData.default();

  const expectedResult = verifyAssertionResponse(options);

  expect(result).toEqual(expectedResult);
});

it('should have consistent data across utils', () => {
  const { options } = VerifyAssertionResponseTestingData.default();
  const { result } = GenerateAssertionOptionsTestingData.withAllowCredentials();

  expect(result.allowCredentials?.[0].id).toEqual(options.credential.id);
});
