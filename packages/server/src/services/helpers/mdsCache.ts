import { SimpleWebAuthnError } from '../../errors/index.ts';
import { convertAAGUIDToString } from '../../helpers/convertAAGUIDToString.ts';
import type { Uint8Array_ } from '../../types/index.ts';

// Type aliases to try and convey the type of string value that should be used in the Maps below
/** A full URL string, including protocol (e.g. `https://example.com`) */
export type MDSServerURL = string;
/** A lowercase AAGUID string (e.g. `3add0b21-6513-4323-81a2-74c78f3ea651`) */
export type AAGUID = string;

// Cached (C-)MDS APIs from which metadata entries are downloaded
export type CachedMDSServer = {
  url: MDSServerURL;
  no: number;
  nextUpdate: Date;
};
export const NonRefreshingURL = '';

/**
 * An MDS-aware metadata cache that tracks MDS servers and the data downloaded from them. This
 * includes tracking when an MDS server needs to be refreshed, but does not actually perform the
 * refresh.
 */
export class MDSCache<MetadataType> {
  private serverCache: Map<MDSServerURL, CachedMDSServer> = new Map();
  private metadataCache: Map<
    AAGUID,
    { data: MetadataType; url: CachedMDSServer['url'] }
  > = new Map();

  /**
   * Set up a Metadata Service API for periodic refreshes
   */
  registerMDSServer(url: MDSServerURL, no: number, nextUpdate: Date): void {
    this.serverCache.set(url, {
      url,
      // Store the payload `no` (aka "serial number", "version number", etc...) to skip
      // re-downloading metadata we already have the latest
      no,
      // When this MDS server should be checked for new data
      nextUpdate,
    });
  }

  /**
   * Add the provided metadata to the cache, keyed by its corresponding AAGUID
   */
  cacheMetadata(aaguid: AAGUID, metadata: MetadataType, url: MDSServerURL): void {
    this.metadataCache.set(this.normalizeAAGUID(aaguid), { data: metadata, url });
  }

  /**
   * Retrieve cached metadata by AAGUID
   */
  getMetadata(aaguid: AAGUID | Uint8Array_): MetadataType | undefined {
    if (!aaguid) {
      return;
    }

    if (aaguid instanceof Uint8Array) {
      aaguid = convertAAGUIDToString(aaguid);
    }

    return this.metadataCache.get(this.normalizeAAGUID(aaguid))?.data;
  }

  /**
   * Return how many metadata entries have been cached
   */
  get count(): number {
    return this.metadataCache.size;
  }

  /**
   * Clear out caches
   */
  reset(): void {
    this.serverCache = new Map();
    this.metadataCache = new Map();
  }

  /**
   * Remove cached Metadata Service data for a specific API server. If the URL indicates data that
   * should not be refreshed, then simply exit.
   */
  clearMetadataByURL(url: MDSServerURL): void {
    // Do _not_ clear out entries that aren't associated with an MDS service
    if (url === NonRefreshingURL) {
      return;
    }

    for (const [aaguid, cached] of this.metadataCache.entries()) {
      if (cached.url === url) {
        this.metadataCache.delete(this.normalizeAAGUID(aaguid));
      }
    }
  }

  /**
   * Set the MDS server's nextUpdate
   */
  setMDSServerNextUpdate(url: MDSServerURL, newNextUpdate: Date): void {
    const server = this.serverCache.get(url);

    // This should never happen, but just in case...
    if (!server) {
      throw new SimpleWebAuthnError({
        message:
          `No MDS server has been registered for "${url}". Register it with registerMDSServer() first`,
        code: 'BAD_ARGUMENT',
      });
    }

    server.nextUpdate = newNextUpdate;

    this.serverCache.set(url, server);
  }

  /**
   * Retrieve the version number of the MDS server's latest known data
   */
  getMDSServerDataVersion(url: MDSServerURL): CachedMDSServer['no'] {
    const server = this.serverCache.get(url);

    // This should never happen, but just in case...
    if (!server) {
      throw new SimpleWebAuthnError({
        message:
          `No MDS server has been registered for "${url}". Register it with registerMDSServer() first`,
        code: 'BAD_ARGUMENT',
      });
    }

    return server.no;
  }

  /**
   * Return a list of MDS server URLs with nextUpdates earlier than the provided date
   */
  getStaleMDSServerURLs(date: Date): MDSServerURL[] {
    const staleURLs = this.serverCache.values()
      .filter((mds) => mds.url !== NonRefreshingURL && date > mds.nextUpdate)
      .map((mds) => mds.url);

    return staleURLs.toArray();
  }

  /**
   * Ensure that AAGUIDs are all lowercase before using them as cache keys
   */
  private normalizeAAGUID(aaguid: AAGUID): AAGUID {
    return aaguid.toLowerCase();
  }
}
