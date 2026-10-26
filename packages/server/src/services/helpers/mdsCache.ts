import { SimpleWebAuthnError } from '../../errors/index.ts';
import { convertAAGUIDToString } from '../../helpers/index.ts';
import type { Uint8Array_ } from '../../types/index.ts';

// Cached (C-)MDS APIs from which metadata entries are downloaded
export type CachedMDSServer = {
  url: string;
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
  private serverCache: { [url: string]: CachedMDSServer } = {};
  private metadataCache: {
    [aaguid: string]: { data: MetadataType; url: CachedMDSServer['url'] } | undefined;
  } = {};

  /**
   * Set up a Metadata Service API for periodic refreshes
   */
  registerMDSServer(url: string, no: number, nextUpdate: Date): void {
    this.serverCache[url] = {
      url,
      // Store the payload `no` (aka "serial number", "version number", etc...) to skip
      // re-downloading metadata we already have the latest
      no,
      // When this MDS server should be checked for new data
      nextUpdate,
    };
  }

  /**
   * Add the provided metadata to the cache, keyed by its corresponding AAGUID
   */
  cacheMetadata(aaguid: string, metadata: MetadataType, url: string): void {
    this.metadataCache[aaguid] = { data: metadata, url };
  }

  /**
   * Retrieve cached metadata by AAGUID
   */
  getMetadata(aaguid: string | Uint8Array_): MetadataType | undefined {
    if (!aaguid) {
      return;
    }

    if (aaguid instanceof Uint8Array) {
      aaguid = convertAAGUIDToString(aaguid);
    }

    return this.metadataCache[aaguid]?.data;
  }

  /**
   * Return how many metadata entries have been cached
   */
  get count(): number {
    return Object.keys(this.metadataCache).length;
  }

  /**
   * Clear out caches
   */
  reset(): void {
    this.serverCache = {};
    this.metadataCache = {};
  }

  /**
   * Remove cached Metadata Service data for a specific API server. If the URL indicates data that
   * should not be refreshed, then simply exit.
   */
  clearMetadataByURL(url: string): void {
    // Do _not_ clear out entries that aren't associated with an MDS service
    if (url === NonRefreshingURL) {
      return;
    }

    for (const [aaguid, cached] of Object.entries(this.metadataCache)) {
      if (cached?.url === url) {
        delete this.metadataCache[aaguid];
      }
    }
  }

  /**
   * Set the MDS server's nextUpdate
   */
  setMDSServerNextUpdate(url: string, newNextUpdate: Date): void {
    // This should never happen, but just in case...
    if (!this.serverCache[url]) {
      throw new SimpleWebAuthnError({
        message:
          `No MDS server has been registered for "${url}". Register it with registerMDSServer() first`,
        code: 'BAD_ARGUMENT',
      });
    }

    this.serverCache[url].nextUpdate = newNextUpdate;
  }

  /**
   * Retrieve the version number of the MDS server's latest known data
   */
  getMDSServerDataVersion(url: string): CachedMDSServer['no'] {
    // This should never happen, but just in case...
    if (!this.serverCache[url]) {
      throw new SimpleWebAuthnError({
        message:
          `No MDS server has been registered for "${url}". Register it with registerMDSServer() first`,
        code: 'BAD_ARGUMENT',
      });
    }

    return this.serverCache[url].no;
  }

  /**
   * Return a list of MDS server URLs with nextUpdates earlier than the provided date
   */
  getStaleMDSServerURLs(date: Date): string[] {
    const staleURLs = Object.values(this.serverCache)
      .filter((mds) => mds.url !== NonRefreshingURL && date > mds.nextUpdate)
      .map((mds) => mds.url);

    return staleURLs;
  }
}
