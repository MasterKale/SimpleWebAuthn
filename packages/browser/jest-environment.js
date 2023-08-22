import { TestEnvironment } from 'jest-environment-jsdom';

/**
 * Set up a custom JSDOM-based test environment for Jest so we can add things JSDOM doesn't support
 */
class CustomTestEnvironment extends TestEnvironment {
  async setup() {
    await super.setup();
    /**
     * JSDOM doesn't implement TextEncoder so we need to fake it with Node's
     *
     * Solved thanks to https://stackoverflow.com/a/57713960/2133271
     */
    if (typeof this.global.TextEncoder === 'undefined') {
      const { TextEncoder } = await import('util');
      this.global.TextEncoder = TextEncoder;
    }

    /**
     * Add support for TextDecoder to JSDOM
     */
    if (typeof this.global.TextDecoder === 'undefined') {
      const { TextDecoder } = await import('util');
      this.global.TextDecoder = TextDecoder;
    }
  }
}

export default CustomTestEnvironment;
