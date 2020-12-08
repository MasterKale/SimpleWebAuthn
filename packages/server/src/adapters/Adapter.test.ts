import Adapter from './Adapter';
import { getVerifyAssertOptions, getAssertResponse } from '../assertion/testHelper';
import { getAttestResponse, getVerifyAttestOptions } from '../attestation/testHelper';

test('should assert', () => {
  const res = getAssertResponse();
  expect(Adapter.prototype.assert(res)).toEqual(res);
});

test('should verify assert', () => {
  const options = getVerifyAssertOptions();
  expect(Adapter.prototype.verifyAssert(options)).toEqual(options);
});

test('should attest', () => {
  const res = getAttestResponse();
  expect(Adapter.prototype.attest(res)).toEqual(res);
});

test('should verify attest', () => {
  const options = getVerifyAttestOptions();
  expect(Adapter.prototype.verifyAttest(options)).toEqual(options);
});
