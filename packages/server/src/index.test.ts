import * as index from './index';

test('should export method `generateRegistrationOptions`', () => {
  expect(index.generateRegistrationOptions).toBeDefined();
});

test('should export method `verifyRegistrationResponse`', () => {
  expect(index.verifyRegistrationResponse).toBeDefined();
});

test('should export method `generateAssertionOptions`', () => {
  expect(index.generateAssertionOptions).toBeDefined();
});

test('should export method `verifyAssertionResponse`', () => {
  expect(index.verifyAssertionResponse).toBeDefined();
});
