// Silence some console output
// jest.spyOn(console, 'log').mockImplementation();
// jest.spyOn(console, 'debug').mockImplementation();
// jest.spyOn(console, 'error').mockImplementation();

/**
 * JSDom doesn't seem to support `credentials`, so let's define them here so we can mock their
 * implementations in specific tests.
 */
Object.defineProperty(window.navigator, 'credentials', {
  writable: true,
  value: {
    create: jest.fn(),
    get: jest.fn(),
  },
});

/**
 * Allow for setting values to `window.location.hostname`
 */
Object.defineProperty(window, 'location', {
  writable: true,
  value: {
    hostname: '',
  },
});

/**
 * Define WebAuthn's custom API errors
 */

class AbortError extends Error {
  constructor() {
    super();
    this.name = 'AbortError';
  }
}

class ConstraintError extends Error {
  constructor() {
    super();
    this.name = 'ConstraintError';
  }
}

class InvalidStateError extends Error {
  constructor() {
    super();
    this.name = 'InvalidStateError';
  }
}

class NotAllowedError extends Error {
  constructor() {
    super();
    this.name = 'NotAllowedError';
  }
}

class NotSupportedError extends Error {
  constructor() {
    super();
    this.name = 'NotSupportedError';
  }
}

class SecurityError extends Error {
  constructor() {
    super();
    this.name = 'SecurityError';
  }
}

class UnknownError extends Error {
  constructor() {
    super();
    this.name = 'UnknownError';
  }
}

Object.defineProperty(global, 'AbortError', { value: AbortError });
Object.defineProperty(global, 'ConstraintError', { value: ConstraintError });
Object.defineProperty(global, 'InvalidStateError', { value: InvalidStateError });
Object.defineProperty(global, 'NotAllowedError', { value: NotAllowedError });
Object.defineProperty(global, 'NotSupportedError', { value: NotSupportedError });
Object.defineProperty(global, 'SecurityError', { value: SecurityError });
Object.defineProperty(global, 'UnknownError', { value: UnknownError });
