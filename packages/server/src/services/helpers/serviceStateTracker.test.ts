import { assertEquals, assertRejects } from '@std/assert';
import { afterEach, beforeEach, describe, it } from '@std/testing/bdd';
import { assertSpyCallArg, assertSpyCalls, type Spy, spy } from '@std/testing/mock';
import { FakeTime } from '@std/testing/time';

import type { SimpleWebAuthnLogger } from '../../helpers/logging.ts';
import { SERVICE_STATE, ServiceStateTracker } from './serviceStateTracker.ts';

let time: FakeTime;
let debugSpy: Spy;
let tracker: ServiceStateTracker;

beforeEach(() => {
  time = new FakeTime();
  debugSpy = spy();
  const logger: Required<SimpleWebAuthnLogger> = {
    debug: debugSpy,
    info: () => {},
    warn: () => {},
    error: () => {},
  };
  tracker = new ServiceStateTracker('TestService', logger);
});

afterEach(() => {
  time.restore();
});

describe('Property: current', () => {
  it('should start out DISABLED', () => {
    assertEquals(tracker.current, SERVICE_STATE.DISABLED);
  });

  it('should reflect the most recently set state', () => {
    tracker.set(SERVICE_STATE.REFRESHING);
    assertEquals(tracker.current, SERVICE_STATE.REFRESHING);

    tracker.set(SERVICE_STATE.READY);
    assertEquals(tracker.current, SERVICE_STATE.READY);

    tracker.set(SERVICE_STATE.DISABLED);
    assertEquals(tracker.current, SERVICE_STATE.DISABLED);
  });
});

describe('Method: set()', () => {
  it('should not log anything on construction', () => {
    assertSpyCalls(debugSpy, 0);
  });

  it('should log each state change with the service name', () => {
    tracker.set(SERVICE_STATE.REFRESHING);
    tracker.set(SERVICE_STATE.READY);
    tracker.set(SERVICE_STATE.DISABLED);

    assertSpyCalls(debugSpy, 3);
    assertSpyCallArg(debugSpy, 0, 0, 'TestService is REFRESHING');
    assertSpyCallArg(debugSpy, 1, 0, 'TestService is READY');
    assertSpyCallArg(debugSpy, 2, 0, 'TestService is DISABLED');
  });
});

describe('Method: pauseUntilReady()', () => {
  it('should resolve immediately when already READY', async () => {
    tracker.set(SERVICE_STATE.READY);

    // No timers are advanced, so this only resolves if no polling is needed
    await tracker.pauseUntilReady();
  });

  it('should not resolve while REFRESHING', async () => {
    tracker.set(SERVICE_STATE.REFRESHING);

    let resolved = false;
    const paused = tracker.pauseUntilReady().then(() => {
      resolved = true;
    });

    await time.tickAsync(5_000);
    assertEquals(resolved, false);

    tracker.set(SERVICE_STATE.READY);
    await time.tickAsync(100);
    await paused;
    assertEquals(resolved, true);
  });

  it('should not resolve while DISABLED', async () => {
    tracker.set(SERVICE_STATE.DISABLED);

    let resolved = false;
    const paused = tracker.pauseUntilReady().then(() => {
      resolved = true;
    });

    await time.tickAsync(5_000);
    assertEquals(resolved, false);

    tracker.set(SERVICE_STATE.READY);
    await time.tickAsync(100);
    await paused;
    assertEquals(resolved, true);
  });

  it('should resolve within one polling interval of becoming READY', async () => {
    /**
     * This test will fail if `intervalMS` inside of `ServiceStateTracker.pauseUntilReady()` is
     * changed to something else. It's set to 100 which is why the ticks below are broken up into
     * 99 + 1.
     */
    tracker.set(SERVICE_STATE.REFRESHING);

    let resolved = false;
    const paused = tracker.pauseUntilReady().then(() => {
      resolved = true;
    });

    await time.tickAsync(1_000);
    tracker.set(SERVICE_STATE.READY);

    await time.tickAsync(99);
    assertEquals(resolved, false);

    await time.tickAsync(1);
    await paused;
    assertEquals(resolved, true);
  });

  it('should resolve every waiter when the service becomes READY', async () => {
    tracker.set(SERVICE_STATE.REFRESHING);

    const resolved: number[] = [];
    const waiters = [1, 2, 3].map((n) =>
      tracker.pauseUntilReady().then(() => {
        resolved.push(n);
      })
    );

    tracker.set(SERVICE_STATE.READY);
    await time.tickAsync(100);
    await Promise.all(waiters);

    assertEquals(resolved.sort(), [1, 2, 3]);
  });

  it('should reject if the service does not become READY within 70 seconds', async () => {
    tracker.set(SERVICE_STATE.REFRESHING);

    // Start waiting before advancing time so the rejection is never left unhandled
    const rejection = assertRejects(() => tracker.pauseUntilReady());

    await time.tickAsync(70_200);

    // `pauseUntilReady()` rejects with a string, which `assertRejects()` hands back as-is
    assertEquals(await rejection, 'State did not become ready in 70 seconds');
  });

  it('should not reject until the 70 second timeout has elapsed', async () => {
    tracker.set(SERVICE_STATE.REFRESHING);

    let settled = false;
    const rejection = assertRejects(() => tracker.pauseUntilReady()).finally(() => {
      settled = true;
    });

    await time.tickAsync(69_900);
    assertEquals(settled, false);

    await time.tickAsync(300);
    await rejection;
    assertEquals(settled, true);
  });

  it('should stop polling after resolving', async () => {
    tracker.set(SERVICE_STATE.REFRESHING);

    const paused = tracker.pauseUntilReady();
    tracker.set(SERVICE_STATE.READY);
    await time.tickAsync(100);
    await paused;

    // Leaving the state alone and advancing past the timeout must not cause a late rejection
    tracker.set(SERVICE_STATE.REFRESHING);
    await time.tickAsync(80_000);
  });
});
