import { assertEquals } from '@std/assert';
import { afterEach, beforeEach, describe, it } from '@std/testing/bdd';
import {
  assertSpyCallArg,
  assertSpyCalls,
  returnsNext,
  spy,
  type Stub,
  stub,
} from '@std/testing/mock';
import { FakeTime } from '@std/testing/time';

import { _fetchInternals } from '../helpers/fetch.ts';
import { isoUint8Array } from '../helpers/iso/index.ts';
import type { ConvenienceMDSPayload, ProviderMetadata } from '../metadata/convenienceMDSTypes.ts';
import { BaseConvenienceMetadataService } from './convenienceMetadataService.ts';

const cmdsURL = 'https://cmds.example.com/';
const serverAAGUID = '00000000-0000-0000-0000-000000000003';
const originalMetadata: ProviderMetadata = { friendlyNames: { en: 'Original Name' } };
const updatedMetadata: ProviderMetadata = { friendlyNames: { en: 'Updated Name' } };
const localAAGUID = 'db3d2b77-1fdf-46fa-a07e-b9f1711edec1';
const localMetadata: ProviderMetadata = {
  friendlyNames: { en: 'Local Provider', fr: 'Fournisseur local' },
};
const localPayload = { no: 1, [localAAGUID]: localMetadata } as ConvenienceMDSPayload;
const eightDaysMS = 1000 * 60 * 60 * 24 * 8;

let service: BaseConvenienceMetadataService;
let mockFetch: Stub;

/**
 * Replace `fetch()` with a stub that returns the provided responses, in order
 */
function stubFetch(...responses: Promise<Response>[]) {
  mockFetch.restore();
  mockFetch = stub(_fetchInternals, 'stubThis', returnsNext(responses));
}

/**
 * Initialize with a C-MDS server that responds with `no: 1` and `originalMetadata`. Any
 * `followUps` are returned by subsequent requests. `mockFetch` will have been called once after
 * this finishes
 */
async function initializeWithServer(...followUps: Promise<Response>[]) {
  stubFetch(
    Promise.resolve(Response.json({ no: 1, [serverAAGUID]: originalMetadata })),
    ...followUps,
  );

  await service.initialize({ mdsServers: [cmdsURL] });
}

beforeEach(() => {
  service = new BaseConvenienceMetadataService();
  mockFetch = stub(_fetchInternals, 'stubThis');
});

afterEach(() => {
  mockFetch.restore();
});

describe('Method: initialize()', () => {
  it('should default to querying the official convenience MDS', async () => {
    await service.initialize();

    assertSpyCalls(mockFetch, 1);
    assertSpyCallArg(mockFetch, 0, 0, 'https://c-mds.fidoalliance.org/?localCopySerial=0');
  });

  it('should query provided server URLs', async () => {
    const mdsServers = ['https://custom-cmds1.com', 'https://custom-cmds2.com'];

    await service.initialize({ mdsServers });

    assertSpyCalls(mockFetch, mdsServers.length);
    assertSpyCallArg(mockFetch, 0, 0, 'https://custom-cmds1.com/?localCopySerial=0');
    assertSpyCallArg(mockFetch, 1, 0, 'https://custom-cmds2.com/?localCopySerial=0');
  });

  it('should not query any servers on empty list of URLs', async () => {
    await service.initialize({ mdsServers: [] });

    assertSpyCalls(mockFetch, 0);
  });

  it('should load local payloads', async () => {
    await service.initialize({ mdsServers: [], payloads: [localPayload] });

    assertEquals(await service.getProviderMetadata(localAAGUID), localMetadata);
  });

  it('should load local payloads without querying any servers', async () => {
    await service.initialize({ mdsServers: [], payloads: [localPayload] });

    assertSpyCalls(mockFetch, 0);
  });

  it('should load metadata from multiple local payloads', async () => {
    const otherAAGUID = '00000000-0000-0000-0000-000000000002';
    const otherMetadata: ProviderMetadata = { friendlyNames: { en: 'Other Provider' } };

    await service.initialize({
      mdsServers: [],
      payloads: [
        localPayload,
        { no: 1, [otherAAGUID]: otherMetadata } as ConvenienceMDSPayload,
      ],
    });

    assertEquals(await service.getProviderMetadata(localAAGUID), localMetadata);
    assertEquals(await service.getProviderMetadata(otherAAGUID), otherMetadata);
  });

  it('should load metadata from a server', async () => {
    stubFetch(Promise.resolve(Response.json(localPayload)));

    await service.initialize({ mdsServers: ['https://custom-cmds.com'] });

    assertEquals(await service.getProviderMetadata(localAAGUID), localMetadata);
  });

  it('should move on if a server cannot be reached', async () => {
    stubFetch(
      Promise.reject(new Error('Network down')),
      Promise.resolve(Response.json(localPayload)),
    );

    await service.initialize({
      mdsServers: ['https://broken-cmds.com', 'https://working-cmds.com'],
    });

    assertEquals(await service.getProviderMetadata(localAAGUID), localMetadata);
  });

  it('should use local payloads as a fallback to servers', async () => {
    // Three AAGUIDs, each present in a different combination of sources:
    //   sharedAAGUID     -> in a local payload AND in the server response
    //   serverOnlyAAGUID -> in the server response only
    //   localOnlyAAGUID  -> in a local payload only
    const sharedAAGUID = '00000000-0000-0000-0000-000000000003';
    const serverOnlyAAGUID = '00000000-0000-0000-0000-000000000004';
    const localOnlyAAGUID = '00000000-0000-0000-0000-000000000005';
    const sharedLocalMetadata: ProviderMetadata = { friendlyNames: { en: 'Shared (local)' } };
    const sharedServerMetadata: ProviderMetadata = { friendlyNames: { en: 'Shared (server)' } };
    const serverOnlyMetadata: ProviderMetadata = { friendlyNames: { en: 'Server only' } };
    const localOnlyMetadata: ProviderMetadata = { friendlyNames: { en: 'Local only' } };

    stubFetch(
      Promise.resolve(Response.json({
        no: 1,
        [sharedAAGUID]: sharedServerMetadata,
        [serverOnlyAAGUID]: serverOnlyMetadata,
      })),
    );

    await service.initialize({
      mdsServers: ['https://custom-cmds.com'],
      payloads: [
        { no: 1, [sharedAAGUID]: sharedLocalMetadata } as ConvenienceMDSPayload,
        { no: 1, [localOnlyAAGUID]: localOnlyMetadata } as ConvenienceMDSPayload,
      ],
    });

    // When local and server both declare the same AAGUID, the server's metadata replaces the local metadata
    assertEquals(await service.getProviderMetadata(sharedAAGUID), sharedServerMetadata);
    // Only the server specifies this AAGUID so its metadata is loaded normally
    assertEquals(await service.getProviderMetadata(serverOnlyAAGUID), serverOnlyMetadata);
    // Only a local payload has this AAGUID so the server doesn't override it
    assertEquals(await service.getProviderMetadata(localOnlyAAGUID), localOnlyMetadata);
  });

  it('should discard previously-loaded metadata when called again', async () => {
    await service.initialize({ mdsServers: [], payloads: [localPayload] });
    assertEquals(await service.getProviderMetadata(localAAGUID), localMetadata);

    await service.initialize({
      mdsServers: [],
      payloads: [{ no: 1, [serverAAGUID]: originalMetadata } as ConvenienceMDSPayload],
    });

    assertEquals(await service.getProviderMetadata(localAAGUID), undefined);
    assertEquals(await service.getProviderMetadata(serverAAGUID), originalMetadata);
  });

  it('should still be usable when every server fails', async () => {
    stubFetch(Promise.reject(new Error('Network down')));

    await service.initialize({ mdsServers: [cmdsURL] });

    assertEquals(await service.getProviderMetadata(serverAAGUID), undefined);
  });

  it('should hold lookups until initialization has finished', async () => {
    using time = new FakeTime();
    let respond!: (response: Response) => void;
    stubFetch(new Promise<Response>((resolve) => (respond = resolve)));

    const initialization = service.initialize({ mdsServers: [cmdsURL] });

    let result: ProviderMetadata | undefined;
    let settled = false;
    const lookup = service.getProviderMetadata(serverAAGUID).then((metadata) => {
      result = metadata;
      settled = true;
    });

    await time.tickAsync(1_000);
    assertEquals(settled, false);

    respond(Response.json({ no: 1, [serverAAGUID]: originalMetadata }));
    await initialization;
    await time.tickAsync(100);
    await lookup;

    assertEquals(settled, true);
    assertEquals(result, originalMetadata);
  });
});

describe('Method: getProviderMetadata()', () => {
  it('should return undefined if service not initialized', async () => {
    assertEquals(await service.getProviderMetadata('not-a-real-aaguid'), undefined);
  });

  it('should return undefined if aaguid is undefined', async () => {
    await service.initialize({ mdsServers: [], payloads: [localPayload] });

    // @ts-ignore: intentionally passing a bad value
    assertEquals(await service.getProviderMetadata(undefined), undefined);
  });

  it('should return undefined for an AAGUID with no metadata', async () => {
    await service.initialize({ mdsServers: [], payloads: [localPayload] });

    assertEquals(await service.getProviderMetadata('not-a-real-aaguid'), undefined);
  });

  it('should accept the AAGUID as a Uint8Array', async () => {
    await service.initialize({ mdsServers: [], payloads: [localPayload] });

    const aaguidBytes = isoUint8Array.fromHex(localAAGUID.replaceAll('-', ''));

    assertEquals(await service.getProviderMetadata(aaguidBytes), localMetadata);
  });

  it('should treat AAGUIDs as case-insensitive', async () => {
    await service.initialize({
      mdsServers: [],
      payloads: [{ no: 1, [localAAGUID.toUpperCase()]: localMetadata } as ConvenienceMDSPayload],
    });

    assertEquals(await service.getProviderMetadata(localAAGUID), localMetadata);
    assertEquals(await service.getProviderMetadata(localAAGUID.toUpperCase()), localMetadata);
  });

  it('should not refresh metadata from a current server', async () => {
    await initializeWithServer();

    const metadata = await service.getProviderMetadata(serverAAGUID);

    assertSpyCalls(mockFetch, 1);
    assertEquals(metadata, originalMetadata);
  });

  it('should not refresh metadata from local payloads', async () => {
    using time = new FakeTime();
    await service.initialize({ mdsServers: [], payloads: [localPayload] });

    time.tick(eightDaysMS);

    const metadata = await service.getProviderMetadata(localAAGUID);

    assertSpyCalls(mockFetch, 0);
    assertEquals(metadata, localMetadata);
  });
});

describe('Behavior: refreshing stale metadata', () => {
  it('should return up-to-date metadata after refreshing a stale server', async () => {
    using time = new FakeTime();
    await initializeWithServer(
      Promise.resolve(Response.json({ no: 2, [serverAAGUID]: updatedMetadata })),
    );

    time.tick(eightDaysMS);

    const metadata = await service.getProviderMetadata(serverAAGUID);

    assertSpyCalls(mockFetch, 2);
    // Confirm a check for an updated payload using the old serial
    assertSpyCallArg(mockFetch, 1, 0, `${cmdsURL}?localCopySerial=1`);
    // Getting the updated metadata means the internal cache was refreshed correctly
    assertEquals(metadata, updatedMetadata);
  });

  it('should discover an AAGUID added to the server since the last refresh', async () => {
    using time = new FakeTime();
    const newAAGUID = '00000000-0000-0000-0000-000000000006';
    const newMetadata: ProviderMetadata = { friendlyNames: { en: 'New Provider' } };
    await initializeWithServer(
      Promise.resolve(
        Response.json({ no: 2, [serverAAGUID]: originalMetadata, [newAAGUID]: newMetadata }),
      ),
    );

    // Not stale yet, so the unknown AAGUID doesn't cause a request
    assertEquals(await service.getProviderMetadata(newAAGUID), undefined);
    assertSpyCalls(mockFetch, 1);

    time.tick(eightDaysMS);

    // The lookup for an uncached AAGUID is what triggers the refresh
    assertEquals(await service.getProviderMetadata(newAAGUID), newMetadata);
    assertSpyCalls(mockFetch, 2);
  });

  it('should share one refresh between concurrent lookups', async () => {
    using time = new FakeTime();
    await initializeWithServer(
      Promise.resolve(Response.json({ no: 2, [serverAAGUID]: updatedMetadata })),
    );

    time.tick(eightDaysMS);

    const results = await Promise.all([
      service.getProviderMetadata(serverAAGUID),
      service.getProviderMetadata(serverAAGUID),
      service.getProviderMetadata('not-a-real-aaguid'),
    ]);

    assertSpyCalls(mockFetch, 2);
    assertEquals(results, [updatedMetadata, updatedMetadata, undefined]);
  });

  it('should refresh every stale server', async () => {
    using time = new FakeTime();
    const urls = ['https://cmds1.example.com/', 'https://cmds2.example.com/'];
    stubFetch(
      Promise.resolve(Response.json({ no: 1, [serverAAGUID]: originalMetadata })),
      Promise.resolve(Response.json({ no: 1, [localAAGUID]: localMetadata })),
      Promise.resolve(new Response(null, { status: 304 })),
      Promise.resolve(new Response(null, { status: 304 })),
    );
    await service.initialize({ mdsServers: urls });

    time.tick(eightDaysMS);
    await service.getProviderMetadata(serverAAGUID);

    assertSpyCalls(mockFetch, 4);
    assertSpyCallArg(mockFetch, 2, 0, `${urls[0]}?localCopySerial=1`);
    assertSpyCallArg(mockFetch, 3, 0, `${urls[1]}?localCopySerial=1`);
  });

  it('should evict AAGUIDs removed from the server on refresh', async () => {
    using time = new FakeTime();
    const removedAAGUID = '00000000-0000-0000-0000-000000000004';
    const removedMetadata: ProviderMetadata = { friendlyNames: { en: 'Removed Name' } };

    stubFetch(
      // Initial payload includes two AAGUIDs
      Promise.resolve(
        Response.json({
          no: 1,
          [serverAAGUID]: originalMetadata,
          [removedAAGUID]: removedMetadata,
        }),
      ),
      // The refreshed payload no longer includes `removedAAGUID`
      Promise.resolve(Response.json({ no: 2, [serverAAGUID]: updatedMetadata })),
    );
    await service.initialize({ mdsServers: [cmdsURL] });

    // Sanity check: the second AAGUID is cached before the refresh
    assertEquals(await service.getProviderMetadata(removedAAGUID), removedMetadata);

    time.tick(eightDaysMS);

    assertEquals(await service.getProviderMetadata(serverAAGUID), updatedMetadata);
    assertSpyCalls(mockFetch, 2);

    // The server dropped this AAGUID, so it shouldn't linger in the cache
    assertEquals(await service.getProviderMetadata(removedAAGUID), undefined);
  });

  it('should keep local payload metadata when a server refresh evicts entries', async () => {
    using time = new FakeTime();
    stubFetch(
      Promise.resolve(Response.json({ no: 1, [serverAAGUID]: originalMetadata })),
      Promise.resolve(Response.json({ no: 2, [serverAAGUID]: updatedMetadata })),
    );
    await service.initialize({ mdsServers: [cmdsURL], payloads: [localPayload] });

    time.tick(eightDaysMS);

    assertEquals(await service.getProviderMetadata(serverAAGUID), updatedMetadata);
    assertSpyCalls(mockFetch, 2);

    // Evicting entries that came from the server shouldn't touch entries from local data
    assertEquals(await service.getProviderMetadata(localAAGUID), localMetadata);
  });

  describe('when the refresh does not produce new data', () => {
    const failures: [string, () => Promise<Response>][] = [
      ['responds with HTTP 304', () => Promise.resolve(new Response(null, { status: 304 }))],
      ['responds with HTTP 429', () => Promise.resolve(new Response(null, { status: 429 }))],
      ['responds with HTTP 500', () => Promise.resolve(new Response(null, { status: 500 }))],
      ['returns invalid JSON', () => Promise.resolve(new Response('not json', { status: 200 }))],
      ['cannot be reached', () => Promise.reject(new Error('Network down'))],
    ];

    for (const [description, followUp] of failures) {
      it(`should keep cached metadata when the server ${description}`, async () => {
        using time = new FakeTime();
        await initializeWithServer(followUp());

        time.tick(eightDaysMS);

        const metadata = await service.getProviderMetadata(serverAAGUID);

        assertSpyCalls(mockFetch, 2);
        assertEquals(metadata, originalMetadata);

        // A subsequent call shouldn't hang waiting for a ready state
        assertEquals(await service.getProviderMetadata(serverAAGUID), originalMetadata);
      });
    }
  });

  describe('refresh delays', () => {
    const hourMS = 1000 * 60 * 60;

    /**
     * Make a stale refresh attempt that gets `followUp`, then confirm no further requests happen
     * until `delayHours` has passed, and that one more happens right after.
     */
    async function assertDelay(followUp: Promise<Response>, delayHours: number) {
      using time = new FakeTime();
      await initializeWithServer(followUp);

      time.tick(eightDaysMS);
      await service.getProviderMetadata(serverAAGUID);
      // `mockFetch` was called a second time to try and refresh data
      assertSpyCalls(mockFetch, 2);

      // Still within the delay, so no new request
      time.tick((delayHours * hourMS) - 1000);
      await service.getProviderMetadata(serverAAGUID);
      assertSpyCalls(mockFetch, 2);

      // Delay elapsed, so another attempt is made
      stubFetch(Promise.resolve(new Response(null, { status: 304 })));
      time.tick(2000);
      await service.getProviderMetadata(serverAAGUID);
      assertSpyCalls(mockFetch, 1);
    }

    it('should wait 24 hours after an HTTP 304', async () => {
      await assertDelay(Promise.resolve(new Response(null, { status: 304 })), 24);
    });

    it('should wait 3 hours after an HTTP 429', async () => {
      await assertDelay(Promise.resolve(new Response(null, { status: 429 })), 3);
    });

    it('should wait 3 hours after an HTTP 500', async () => {
      await assertDelay(Promise.resolve(new Response(null, { status: 500 })), 3);
    });

    it('should wait 3 hours after a fetch error', async () => {
      await assertDelay(Promise.reject(new Error('Network down')), 3);
    });

    it('should wait 24 hours after a successful refresh', async () => {
      await assertDelay(
        Promise.resolve(Response.json({ no: 2, [serverAAGUID]: updatedMetadata })),
        24,
      );
    });

    describe('when a server fails its initial download', () => {
      const failures: [string, () => Promise<Response>][] = [
        ['cannot be reached', () => Promise.reject(new Error('Network down'))],
        ['responds with HTTP 429', () => Promise.resolve(new Response(null, { status: 429 }))],
        ['responds with HTTP 500', () => Promise.resolve(new Response(null, { status: 500 }))],
        ['returns invalid JSON', () => Promise.resolve(new Response('nope', { status: 200 }))],
      ];

      for (const [description, failure] of failures) {
        it(`should not track the server when it ${description}`, async () => {
          using time = new FakeTime();
          stubFetch(failure());
          await service.initialize({ mdsServers: [cmdsURL], payloads: [localPayload] });
          assertSpyCalls(mockFetch, 1);

          // No data was cached from the server, so it isn't refreshed no matter how long it's been
          time.tick(eightDaysMS);
          assertEquals(await service.getProviderMetadata(serverAAGUID), undefined);
          assertSpyCalls(mockFetch, 1);

          // Local data is unaffected
          assertEquals(await service.getProviderMetadata(localAAGUID), localMetadata);
        });
      }

      it('should report HTTP failures as warnings, not errors', async () => {
        const warnSpy = spy();
        const errorSpy = spy();
        stubFetch(Promise.resolve(new Response(null, { status: 500 })));

        await service.initialize({
          mdsServers: [cmdsURL],
          logger: { warn: warnSpy, error: errorSpy },
        });

        assertSpyCalls(warnSpy, 1);
        assertSpyCalls(errorSpy, 0);
      });
    });
  });
});

describe('Behavior: logging', () => {
  it('should use provided logger', async () => {
    const debugSpy = spy();
    stubFetch(Promise.resolve(Response.json({ no: 1, [serverAAGUID]: originalMetadata })));

    await service.initialize({ mdsServers: [cmdsURL], logger: { debug: debugSpy } });

    /**
     * The content of the logging is less important here than the fact that the service used the
     * provided logger to communicate internal goings on.
     */
    assertSpyCallArg(debugSpy, 0, 0, 'ConvenienceMetadataService is REFRESHING');
    assertSpyCallArg(debugSpy, 1, 0, 'Cached 1 metadata entries from "https://cmds.example.com/"');
    assertSpyCallArg(debugSpy, 2, 0, 'ConvenienceMetadataService is READY');
  });
});
