import { assertEquals } from '@std/assert';
import { assertSpyCall, spy } from '@std/testing/mock';

import { buildLoggerAllMethods } from './logging.ts';

Deno.test('should define default methods for undefined methods', () => {
  const logger = buildLoggerAllMethods({});

  assertEquals(typeof logger.debug, 'function');
  assertEquals(typeof logger.info, 'function');
  assertEquals(typeof logger.warn, 'function');
  assertEquals(typeof logger.error, 'function');
});

Deno.test('should use provided logger methods', () => {
  const _debugSpy = spy();
  const logger = buildLoggerAllMethods({ debug: _debugSpy });

  logger.debug('SimpleWebAuthn');

  assertEquals(logger.debug, _debugSpy);
  assertSpyCall(_debugSpy, 0, { args: ['SimpleWebAuthn'], returned: undefined });
});
