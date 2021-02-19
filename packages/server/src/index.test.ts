import * as index from './index';

test('should export method `generateAttestationOptions`', () => {
  expect(index.generateAttestationOptions).toBeDefined();
});

test('should export method `verifyAttestationResponse`', () => {
  expect(index.verifyAttestationResponse).toBeDefined();
});

test('should export method `generateAssertionOptions`', () => {
  expect(index.generateAssertionOptions).toBeDefined();
});

test('should export method `verifyAssertionResponse`', () => {
  expect(index.verifyAssertionResponse).toBeDefined();
});

test('should export method `GenerateAssertionOptions`', () => {
  expect(index.GenerateAssertionOptions).toBeDefined();
});

test('should export method `GenerateAttestationOptions`', () => {
  expect(index.GenerateAttestationOptions).toBeDefined();
});

test('should export method `VerifyAttestationOptions`', () => {
  expect(index.VerifyAttestationOptions).toBeDefined();
});

test('should export method `VerifyAssertionOptions`', () => {
  expect(index.VerifyAssertionOptions).toBeDefined();
});

test('should export method `VerifiedAttestation`', () => {
  expect(index.VerifiedAttestation).toBeDefined();
});

test('should export method `VerifiedAssertion`', () => {
  expect(index.VerifiedAssertion).toBeDefined();
});
