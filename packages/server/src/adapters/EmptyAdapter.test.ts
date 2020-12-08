import EmptyAdapter from './EmptyAdapter';
import { getVerifyAssertOptions, getAssertResponse } from '../assertion/testHelper';
import { getAttestResponse, getVerifyAttestOptions } from '../attestation/testHelper';

test('should assert', () => {
  const adapter = new EmptyAdapter();
  const res = getAssertResponse();
  expect(adapter.assert(res)).toEqual(res);
});

test('should verify assert', () => {
  const adapter = new EmptyAdapter();
  const options = getVerifyAssertOptions();
  expect(adapter.verifyAssert(options)).toEqual(options);
});

test('should attest', () => {
  const adapter = new EmptyAdapter();
  const res = getAttestResponse();
  expect(adapter.attest(res)).toEqual(res);
});

test('should verify attest', () => {
  const adapter = new EmptyAdapter();
  const options = getVerifyAttestOptions();
  expect(adapter.verifyAttest(options)).toEqual(options);
});
