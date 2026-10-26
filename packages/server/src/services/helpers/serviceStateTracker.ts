import type { SimpleWebAuthnLogger } from '../../helpers/logging.ts';

export enum SERVICE_STATE {
  DISABLED = 'DISABLED',
  REFRESHING = 'REFRESHING',
  READY = 'READY',
}

export class ServiceStateTracker {
  private state = SERVICE_STATE.DISABLED;

  constructor(
    private readonly name: string,
    private readonly logger: Required<SimpleWebAuthnLogger>,
  ) {}

  /**
   * Get the current state
   */
  get current(): SERVICE_STATE {
    return this.state;
  }

  /**
   * Set a new state and report it
   */
  set(next: SERVICE_STATE) {
    // If we're already in this state then there's nothing to do
    if (this.state === next) {
      return;
    }

    this.state = next;

    this.logger.debug(`${this.name} is ${SERVICE_STATE[this.state]}`);
  }

  /**
   * A helper method to pause execution until the service is ready
   */
  pauseUntilReady(): Promise<void> {
    if (this.state === SERVICE_STATE.READY) {
      return Promise.resolve();
    }

    // State isn't ready, so set up polling
    const readyPromise = new Promise<void>((resolve, reject) => {
      const totalTimeoutMS = 70_000;
      const intervalMS = 100;
      let iterations = totalTimeoutMS / intervalMS;

      // Check service state every `intervalMS` milliseconds
      const intervalID = globalThis.setInterval(() => {
        if (iterations < 1) {
          clearInterval(intervalID);
          reject(`State did not become ready in ${totalTimeoutMS / 1000} seconds`);
        } else if (this.state === SERVICE_STATE.READY) {
          clearInterval(intervalID);
          resolve();
        }

        iterations -= 1;
      }, intervalMS);
    });

    return readyPromise;
  }
}
