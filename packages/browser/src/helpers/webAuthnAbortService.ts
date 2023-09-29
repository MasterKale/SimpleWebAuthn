class BaseWebAuthnAbortService {
  private controller: AbortController | undefined;

  /**
   * Prepare an abort signal that will help support multiple auth attempts without needing to
   * reload the page. This is automatically called whenever `startRegistration()` and
   * `startAuthentication()` are called.
   */
  createNewAbortSignal() {
    // Abort any existing calls to navigator.credentials.create() or navigator.credentials.get()
    if (this.controller) {
      const abortError = new Error(
        'Cancelling existing WebAuthn API call for new one',
      );
      abortError.name = 'AbortError';
      this.controller.abort(abortError);
    }

    const newController = new AbortController();

    this.controller = newController;
    return newController.signal;
  }

  /**
   * Manually cancel any active WebAuthn registration or authentication attempt.
   */
  cancelCeremony() {
    if (this.controller) {
      const abortError = new Error(
        'Manually cancelling existing WebAuthn API call',
      );
      abortError.name = 'AbortError';
      this.controller.abort(abortError);

      this.controller = undefined;
    }
  }
}

/**
 * A service singleton to help ensure that only a single WebAuthn ceremony is active at a time.
 *
 * Users of **@simplewebauthn/browser** shouldn't typically need to use this, but it can help e.g.
 * developers building projects that use client-side routing to better control the behavior of
 * their UX in response to router navigation events.
 */
export const WebAuthnAbortService = new BaseWebAuthnAbortService();
