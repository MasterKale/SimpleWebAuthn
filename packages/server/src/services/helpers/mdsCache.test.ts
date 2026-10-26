import { assertEquals, assertThrows } from '@std/assert';
import { beforeEach, describe, it } from '@std/testing/bdd';

import { SimpleWebAuthnError } from '../../errors/index.ts';
import { isoUint8Array } from '../../helpers/iso/index.ts';
import { MDSCache, NonRefreshingURL } from './mdsCache.ts';

const url = 'https://mds.example.com/';
const otherURL = 'https://other-mds.example.com/';
const aaguid = 'eccafc38-1f85-41ed-8f3f-ea17705ae8b7';

let cache: MDSCache<{ name: string }>;

beforeEach(() => {
  cache = new MDSCache();
});

describe('Method: cacheMetadata() and getMetadata()', () => {
  it('should return cached metadata by AAGUID', () => {
    cache.cacheMetadata(aaguid, { name: 'A' }, url);

    assertEquals(cache.getMetadata(aaguid), { name: 'A' });
  });

  it('should return undefined for an uncached AAGUID', () => {
    assertEquals(cache.getMetadata(aaguid), undefined);
  });

  it('should return undefined for an empty AAGUID', () => {
    // @ts-ignore: intentionally passing a bad value
    assertEquals(cache.getMetadata(undefined), undefined);
    assertEquals(cache.getMetadata(''), undefined);
  });

  it('should accept the AAGUID as a Uint8Array', () => {
    cache.cacheMetadata(aaguid, { name: 'A' }, url);

    const aaguidBytes = isoUint8Array.fromHex(aaguid.replaceAll('-', ''));

    assertEquals(cache.getMetadata(aaguidBytes), { name: 'A' });
  });

  it('should treat AAGUIDs as case-insensitive', () => {
    cache.cacheMetadata(aaguid.toUpperCase(), { name: 'A' }, url);

    assertEquals(cache.getMetadata(aaguid), { name: 'A' });
    assertEquals(cache.getMetadata(aaguid.toUpperCase()), { name: 'A' });
    assertEquals(cache.count, 1);
  });

  it('should overwrite an existing entry for the same AAGUID', () => {
    cache.cacheMetadata(aaguid, { name: 'A' }, NonRefreshingURL);
    cache.cacheMetadata(aaguid, { name: 'B' }, url);

    assertEquals(cache.getMetadata(aaguid), { name: 'B' });
    assertEquals(cache.count, 1);
  });

  it('should not mistake special property names for cached entries', () => {
    cache.cacheMetadata('__proto__', { name: 'A' }, url);

    assertEquals(cache.count, 1);
    assertEquals(cache.getMetadata('data'), undefined);
    assertEquals(cache.getMetadata('url'), undefined);
    assertEquals(cache.getMetadata('toString'), undefined);
  });
});

describe('Property: count', () => {
  it('should be zero for an empty cache', () => {
    assertEquals(cache.count, 0);
  });

  it('should count cached entries', () => {
    cache.cacheMetadata('aaguid-1', { name: 'A' }, url);
    cache.cacheMetadata('aaguid-2', { name: 'B' }, url);

    assertEquals(cache.count, 2);
  });
});

describe('Method: reset()', () => {
  it('should clear cached metadata and registered servers', () => {
    cache.registerMDSServer(url, 1, new Date(0));
    cache.cacheMetadata(aaguid, { name: 'A' }, url);

    cache.reset();

    assertEquals(cache.count, 0);
    assertEquals(cache.getMetadata(aaguid), undefined);
    assertEquals(cache.getStaleMDSServerURLs(new Date()), []);
  });
});

describe('Method: clearMetadataByURL()', () => {
  it('should remove only entries associated with the URL', () => {
    cache.cacheMetadata('aaguid-1', { name: 'A' }, url);
    cache.cacheMetadata('aaguid-2', { name: 'B' }, url);
    cache.cacheMetadata('aaguid-3', { name: 'C' }, otherURL);

    cache.clearMetadataByURL(url);

    assertEquals(cache.getMetadata('aaguid-1'), undefined);
    assertEquals(cache.getMetadata('aaguid-2'), undefined);
    assertEquals(cache.getMetadata('aaguid-3'), { name: 'C' });
    assertEquals(cache.count, 1);
  });

  it('should not remove entries that are not associated with a server', () => {
    cache.cacheMetadata('aaguid-1', { name: 'A' }, NonRefreshingURL);
    cache.cacheMetadata('aaguid-2', { name: 'B' }, url);

    cache.clearMetadataByURL(NonRefreshingURL);

    assertEquals(cache.getMetadata('aaguid-1'), { name: 'A' });
    assertEquals(cache.getMetadata('aaguid-2'), { name: 'B' });
  });

  it('should not remove an entry another server has since overwritten', () => {
    cache.cacheMetadata(aaguid, { name: 'A' }, url);
    cache.cacheMetadata(aaguid, { name: 'B' }, url);

    // Pretend some other server refresh contained this AAGUID
    cache.cacheMetadata(aaguid, { name: 'B' }, otherURL);

    cache.clearMetadataByURL(url);

    assertEquals(cache.getMetadata(aaguid), { name: 'B' });
  });

  it('should do nothing for an unknown URL', () => {
    cache.cacheMetadata(aaguid, { name: 'A' }, url);

    cache.clearMetadataByURL('https://unknown.example.com/');

    assertEquals(cache.count, 1);
  });
});

describe('Method: registerMDSServer()', () => {
  it('should remember the server data version', () => {
    cache.registerMDSServer(url, 5, new Date(0));

    assertEquals(cache.getMDSServerDataVersion(url), 5);
  });

  it('should replace a previous registration for the same URL', () => {
    cache.registerMDSServer(url, 1, new Date(0));
    cache.registerMDSServer(url, 2, new Date(0));

    assertEquals(cache.getMDSServerDataVersion(url), 2);
  });
});

describe('Method: mdsServerIsRegistered()', () => {
  it('should be false for an unregistered URL', () => {
    assertEquals(cache.mdsServerIsRegistered(url), false);
  });

  it('should be true for a registered URL', () => {
    cache.registerMDSServer(url, 1, new Date(0));

    assertEquals(cache.mdsServerIsRegistered(url), true);
    assertEquals(cache.mdsServerIsRegistered(otherURL), false);
  });

  it('should be false after reset()', () => {
    cache.registerMDSServer(url, 1, new Date(0));

    cache.reset();

    assertEquals(cache.mdsServerIsRegistered(url), false);
  });
});

describe('Method: getMDSServerDataVersion()', () => {
  it('should throw for an unregistered URL', () => {
    const error = assertThrows(
      () => cache.getMDSServerDataVersion(url),
      SimpleWebAuthnError,
      'No MDS server has been registered',
    );

    assertEquals(error.code, 'BAD_ARGUMENT');
  });
});

describe('Method: setMDSServerNextUpdate()', () => {
  it('should update when the server becomes stale', () => {
    const now = new Date('2026-10-01T12:00:00Z');
    cache.registerMDSServer(url, 1, new Date('2099-01-01T00:00:00Z'));
    assertEquals(cache.getStaleMDSServerURLs(now), []);

    cache.setMDSServerNextUpdate(url, new Date('2026-10-01T00:00:00Z'));

    assertEquals(cache.getStaleMDSServerURLs(now), [url]);
  });

  it('should not change the server data version', () => {
    cache.registerMDSServer(url, 7, new Date(0));

    cache.setMDSServerNextUpdate(url, new Date());

    assertEquals(cache.getMDSServerDataVersion(url), 7);
  });

  it('should throw for an unregistered URL', () => {
    const error = assertThrows(
      () => cache.setMDSServerNextUpdate(url, new Date()),
      SimpleWebAuthnError,
      'No MDS server has been registered',
    );

    assertEquals(error.code, 'BAD_ARGUMENT');
  });
});

describe('Method: getStaleMDSServerURLs()', () => {
  const now = new Date('2026-10-01T12:00:00Z');

  it('should return an empty list when nothing is registered', () => {
    assertEquals(cache.getStaleMDSServerURLs(now), []);
  });

  it('should return only servers with a nextUpdate before the date', () => {
    cache.registerMDSServer(url, 1, new Date('2026-10-01T00:00:00Z'));
    cache.registerMDSServer(otherURL, 1, new Date('2026-10-02T00:00:00Z'));

    assertEquals(cache.getStaleMDSServerURLs(now), [url]);
  });

  it('should not consider a server stale when nextUpdate equals the date', () => {
    cache.registerMDSServer(url, 1, new Date(now));

    assertEquals(cache.getStaleMDSServerURLs(now), []);
  });

  it('should return multiple stale servers', () => {
    cache.registerMDSServer(url, 1, new Date(0));
    cache.registerMDSServer(otherURL, 1, new Date(0));

    assertEquals(cache.getStaleMDSServerURLs(now), [url, otherURL]);
  });

  it('should never report the non-refreshing URL as stale', () => {
    cache.registerMDSServer(NonRefreshingURL, 1, new Date(0));

    assertEquals(cache.getStaleMDSServerURLs(now), []);
  });
});
