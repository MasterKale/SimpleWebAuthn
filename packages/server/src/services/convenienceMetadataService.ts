import { convertAAGUIDToString } from '../helpers/convertAAGUIDToString.ts';
import {
  buildLoggerAllMethods,
  DefaultNoopLogger,
  SimpleWebAuthnLogger,
} from '../helpers/logging.ts';
import { ConvenienceMDSPayload, ProviderMetadata } from '../metadata/convenienceMDSTypes.ts';
import { Uint8Array_ } from '../types/index.ts';
import { SERVICE_STATE, ServiceStateTracker } from './helpers/serviceStateTracker.ts';

// Cached MDS APIs from which BLOBs are downloaded
type CachedMDS = {
  url: string;
  no: number;
  nextUpdate: Date;
};
/**
 * An instance of `CachedMDS` that will not trigger attempts to refresh the associated entry's blob
 */
const NonRefreshingMDS: CachedMDS = {
  url: '',
  no: 0,
  nextUpdate: new Date(0),
} as const;

type CachedProviderMetadata = {
  metadata: ProviderMetadata;
  url: CachedMDS['url'];
};

const defaultURLConvenienceMDS = 'https://c-mds.fidoalliance.org/';

interface ConvenienceMetadataService {
  /**
   * @param opts.convenienceMDSServers An array of URLs to FIDO Alliance Metadata Convenience
   * Service-compatible servers. Defaults to the official FIDO Convenience MDS
   * @param opts.conveniencePayloads An array of local convenience MDS metadata. Metadata loaded in
   * this way will be loaded but not refreshed. When combined with `convenienceMDSServers`, metadata
   * for the same AAGUID downloaded from a convenience MDS server will replace the local metadata
   * and get refreshed from then on
   * @param opts.logger An instance of `SimpleWebAuthnLogger` that allows for capturing
   * MetadataService log output in a project-specific way
   */
  initialize(opts?: {
    convenienceMDSServers?: string[];
    conveniencePayloads?: ConvenienceMDSPayload[];
    logger?: SimpleWebAuthnLogger;
  }): Promise<void>;
  /**
   * Get localized names and icons for the credential provider associated with the given AAGUID.
   */
  getProviderMetadata(aaguid: string | Uint8Array_): Promise<ProviderMetadata | undefined>;
}

export class BaseConvenienceMetadataService implements ConvenienceMetadataService {
  /**
   * Internal caches
   */
  private mdsCache: { [url: string]: CachedMDS } = {};
  private convenienceMetadataCache: { [aaguid: string]: CachedProviderMetadata | undefined } = {};
  /**
   * Default service state and configuration
   */
  private state = new ServiceStateTracker('ConvenienceMetadataService', DefaultNoopLogger);
  private logger: Required<SimpleWebAuthnLogger> = DefaultNoopLogger;
  /** How many hours to wait to refresh Convenience MDS data */
  private readonly cmdsDefaultRefreshDelayHours = 24;
  /** How many hours to wait to retry a _failed_ attempt to refresh Convenience MDS data */
  private readonly cmdsDefaultRetryDelayHours = 4;

  async initialize(
    opts: {
      convenienceMDSServers?: string[];
      conveniencePayloads?: ConvenienceMDSPayload[];
      logger?: SimpleWebAuthnLogger;
    } = {},
  ): Promise<void> {
    // Reset cache
    this.mdsCache = {};
    this.convenienceMetadataCache = {};

    const {
      convenienceMDSServers = [defaultURLConvenienceMDS],
      conveniencePayloads,
      logger = DefaultNoopLogger,
    } = opts;

    this.logger = buildLoggerAllMethods(logger);
    this.state = new ServiceStateTracker('ConvenienceMetadataService', this.logger);

    this.state.set(SERVICE_STATE.REFRESHING);

    /**
     * If passkey provider metadata is provided, load them into the cache first.
     */
    if (conveniencePayloads?.length) {
      let entriesAdded = 0;

      conveniencePayloads.forEach((payload) => {
        entriesAdded += this.cacheConvenienceMDS(NonRefreshingMDS.url, payload);
      });

      this.logger.info(`Cached ${entriesAdded} local metadata entries`);
    }

    /**
     * If Convenience MDS server URLs are provided, then download and cache the current collection
     * of metadata from them.
     */
    if (convenienceMDSServers?.length) {
      // Get a current count so we know how many new statements we've added from MDS servers
      const currentCacheCount = Object.keys(this.convenienceMetadataCache).length;
      let numServers = convenienceMDSServers.length;

      for (const url of convenienceMDSServers) {
        // Pull convenience metadata
        try {
          const payload = await this.downloadConvenienceMDS(url, 0);

          if (payload) {
            this.cacheConvenienceMDS(url, payload);
          }
        } catch (err) {
          // Notify of the error and move on
          this.logger.error(`Could not download convenience metadata from ${url}:`, err);
          numServers -= 1;
        }
      }

      // Calculate the total number of new metadata entries we successfully added
      const newCacheCount = Object.keys(this.convenienceMetadataCache).length;
      const cacheDiff = newCacheCount - currentCacheCount;
      this.logger.info(
        `Cached ${cacheDiff} metadata entries from ${numServers} convenience metadata server(s)`,
      );
    }

    this.state.set(SERVICE_STATE.READY);
  }

  /**
   * Download the convenience metadata, which is surprisingly just a JSON document
   */
  private async downloadConvenienceMDS(
    url: string,
    no: number,
  ): Promise<ConvenienceMDSPayload | undefined> {
    // Get latest convenience MDS JSON, with a query param that can short-circuit the download
    // if we already have the latest version of metadata
    const _url = new URL(`/?localCopySerial=${no}`, url);
    const resp = await fetch(_url.toString(), { signal: AbortSignal.timeout(10_000) });

    /**
     * We have the latest data, nothing more to do.
     *
     * See https://fidoalliance.org/specs/mds/fido-convenience-metadata-service-v1.0-ps-20250521.html#sctn-mds-blob-proc-rules
     */
    if (resp.status === 304) {
      await resp.body?.cancel();
      this.logger.info(
        `The Convenience MDS API at ${_url.toString()} reported nothing new to download (HTTP 304)`,
      );
      // There's nothing new to download, wait another interval before checking again
      this.delayNextRefresh(url, this.cmdsDefaultRefreshDelayHours);
      return;
    }

    /**
     * The FIDO convenience MDS API aggressively rate-limits so be prepared for that. We'll have to
     * try again later.
     */
    if (resp.status === 429) {
      await resp.body?.cancel();
      this.logger.warn(
        `The Convenience MDS API at ${_url.toString()} rate-limited this request (HTTP 429)`,
      );
      // We checked too soon, wait a bit before checking again
      this.delayNextRefresh(url, this.cmdsDefaultRetryDelayHours);
      return;
    }

    if (!resp.ok) {
      await resp.body?.cancel();
      this.logger.warn(
        `The Convenience MDS API at ${_url.toString()} reported an unsuccessful request (HTTP ${resp.status})`,
      );
      // Likely an HTTP 500 error, but anything not within HTTP 200-299. Wait a bit before trying
      // again
      this.delayNextRefresh(url, this.cmdsDefaultRetryDelayHours);
      return;
    }

    const data: ConvenienceMDSPayload = await resp.json();
    return data;
  }

  /**
   * Cache the AAGUID-keyed entries in a Convenience MDS payload. Returns the number of entries
   * cached (so you can `count += cacheConvenienceMDS(...)`)
   */
  private cacheConvenienceMDS(url: string, payload: ConvenienceMDSPayload): number {
    let entriesAdded = 0;

    // Remove existing entries for this URL
    this.clearCacheEntriesByURL(url);

    // Cache entries
    Object.keys(payload).forEach((aaguid) => {
      // Skip the versioning property
      if (aaguid === 'no') {
        return;
      }

      // The rest of the keys will be AAGUIDs
      this.cacheProviderMetadata(aaguid, payload[aaguid], url);
      entriesAdded += 1;
    });

    // Set up convenience metadata refresh
    this.mdsCache[url] = {
      url,
      // Store the payload `no` to skip re-downloading metadata we already have
      no: payload.no,
      // Convenience MDS returns no nextUpdate, so pick a time in the future
      nextUpdate: new Date(Date.now() + (1000 * 60 * 60 * this.cmdsDefaultRefreshDelayHours)),
    };

    return entriesAdded;
  }

  /**
   * Remove cached Convenience Metadata service data by the URL. If the URL indicates data that
   * should not be refreshed, then simply exit.
   */
  private clearCacheEntriesByURL(url: string): void {
    // Do _not_ clear out entries that aren't associated with a Convenience MDS service
    if (url === NonRefreshingMDS.url) {
      return;
    }

    for (const [aaguid, cached] of Object.entries(this.convenienceMetadataCache)) {
      if (cached?.url === url) {
        delete this.convenienceMetadataCache[aaguid];
      }
    }
  }

  async getProviderMetadata(aaguid: string | Uint8Array_): Promise<ProviderMetadata | undefined> {
    if (this.state.current === SERVICE_STATE.DISABLED) {
      return;
    }

    if (!aaguid) {
      return;
    }

    if (aaguid instanceof Uint8Array) {
      aaguid = convertAAGUIDToString(aaguid);
    }

    // If a cache refresh is in progress then pause this until the service is ready
    await this.state.pauseUntilReady();

    // Try to grab a cached statement
    let cachedMetadata = this.convenienceMetadataCache[aaguid];

    // If the metadata points to a convenience MDS API, then check the nextUpdate to see if we need
    // to refresh it
    if (cachedMetadata?.url) {
      const mds = this.mdsCache[cachedMetadata.url];
      const now = new Date();
      if (now > mds.nextUpdate) {
        try {
          this.state.set(SERVICE_STATE.REFRESHING);
          const payload = await this.downloadConvenienceMDS(mds.url, mds.no);
          if (payload) {
            this.cacheConvenienceMDS(mds.url, payload);
          }

          // Refresh the cached metadata in case the cache got updated just now
          cachedMetadata = this.convenienceMetadataCache[aaguid];
        } catch (err) {
          this.logger.error(`Could not download convenience metadata from ${mds.url}:`, err);
          this.delayNextRefresh(mds.url, this.cmdsDefaultRetryDelayHours);
        } finally {
          this.state.set(SERVICE_STATE.READY);
        }
      }
    }

    if (!cachedMetadata) {
      return;
    }

    const { metadata } = cachedMetadata;

    return metadata;
  }

  /**
   * Cache convenience metadata, whether pulled out of a full-fat `MetadataStatement` or retrieved
   * directly from the Convenience MDS
   */
  private cacheProviderMetadata(aaguid: string, metadata: ProviderMetadata, url: string): void {
    this.convenienceMetadataCache[aaguid] = { metadata, url };
  }

  /**
   * Delay the next refresh attempt of this server by the specified number of hours
   */
  private delayNextRefresh(url: string, numHours: number): void {
    // This should never happen, but just in case...
    if (!this.mdsCache[url]) {
      return;
    }

    this.logger.debug(`Delaying next refresh of ${url} by ${numHours} hours`);
    const numHoursMS = 1000 * 60 * 60 * numHours;
    this.mdsCache[url].nextUpdate = new Date(Date.now() + numHoursMS);
  }
}

/**
 * A basic service for coordinating interactions with the FIDO Convenience Metadata Service. This
 * includes metadata download and parsing, and on-demand requesting and caching of provider details.
 *
 * https://fidoalliance.org/metadata/
 */
export const ConvenienceMetadataService: ConvenienceMetadataService =
  new BaseConvenienceMetadataService();
