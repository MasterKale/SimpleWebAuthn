/**
 * A way to cancel an existing WebAuthn request, for example to cancel a
 * WebAuthn autofill authentication request for a manual authentication attempt.
 */
class WebAuthnAbortService {
  private controller: AbortController | undefined;

  /**
   * Prepare an abort signal that will help support multiple auth attempts without needing to
   * reload the page
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
}

export const webauthnAbortService = new WebAuthnAbortService();
