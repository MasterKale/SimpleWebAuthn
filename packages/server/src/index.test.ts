import { assert } from '@std/assert';

import * as index from './index.ts';

Deno.test('should export method `generateRegistrationOptions`', () => {
  assert(index.generateRegistrationOptions);
});

Deno.test('should export method `verifyRegistrationResponse`', () => {
  assert(index.verifyRegistrationResponse);
});

Deno.test('should export method `generateAuthenticationOptions`', () => {
  assert(index.generateAuthenticationOptions);
});

Deno.test('should export method `verifyAuthenticationResponse`', () => {
  assert(index.verifyAuthenticationResponse);
});

Deno.test('should export service `MetadataService`', () => {
  assert(index.MetadataService);
});

Deno.test('should export service `SettingsService`', () => {
  assert(index.SettingsService);
});
