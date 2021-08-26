import * as index from './index';

test('should export method `generateRegistrationOptions`', () => {
  expect(index.generateRegistrationOptions).toBeDefined();
});

test('should export method `verifyRegistrationResponse`', () => {
  expect(index.verifyRegistrationResponse).toBeDefined();
});

test('should export method `generateAuthenticationOptions`', () => {
  expect(index.generateAuthenticationOptions).toBeDefined();
});

test('should export method `verifyAuthenticationResponse`', () => {
  expect(index.verifyAuthenticationResponse).toBeDefined();
});
