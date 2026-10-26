import { fetch } from '../helpers/fetch.ts';
import {
  buildLoggerAllMethods,
  DefaultNoopLogger,
  type SimpleWebAuthnLogger,
} from '../helpers/logging.ts';
import type { ConvenienceMDSPayload, ProviderMetadata } from '../metadata/convenienceMDSTypes.ts';
import type { Uint8Array_ } from '../types/index.ts';
import { MDSCache, NonRefreshingURL } from './helpers/mdsCache.ts';
import { SERVICE_STATE, ServiceStateTracker } from './helpers/serviceStateTracker.ts';

const defaultURLConvenienceMDS = 'https://c-mds.fidoalliance.org/';

interface ConvenienceMetadataService {
  /**
   * @param opts.mdsServers An array of URLs to FIDO Alliance Convenience Metadata
   * Service (C-MDS)-compatible servers. Defaults to the official FIDO Convenience MDS
   * @param opts.payloads An array of local Convenience Metadata Service payloads. Metadata loaded
   * in this way will be loaded but not refreshed. When combined with `mdsServers`, metadata
   * for the same AAGUID downloaded from a convenience MDS server will replace the local metadata
   * and get refreshed from then on
   * @param opts.logger An instance of `SimpleWebAuthnLogger` that allows for capturing
   * ConvenienceMetadataService log output in a project-specific way
   */
  initialize(opts?: {
    mdsServers?: string[];
    payloads?: ConvenienceMDSPayload[];
    logger?: SimpleWebAuthnLogger;
  }): Promise<void>;
  /**
   * Get localized names and icons for the credential provider associated with the given AAGUID.
   */
  getProviderMetadata(aaguid: string | Uint8Array_): Promise<ProviderMetadata | undefined>;
}

export class BaseConvenienceMetadataService implements ConvenienceMetadataService {
  private serviceName = 'ConvenienceMetadataService';
  /**
   * Internal caches
   */
  private metadataCache = new MDSCache<ProviderMetadata>();
  /**
   * Default service state and configuration
   */
  private state = new ServiceStateTracker(this.serviceName, DefaultNoopLogger);
  private logger: Required<SimpleWebAuthnLogger> = DefaultNoopLogger;
  /** How many hours to wait to refresh Convenience MDS data */
  private readonly cmdsDefaultRefreshDelayHours = 24;
  /** How many hours to wait to retry a _failed_ attempt to refresh Convenience MDS data */
  private readonly cmdsDefaultRetryDelayHours = 4;

  async initialize(
    opts: {
      mdsServers?: string[];
      payloads?: ConvenienceMDSPayload[];
      logger?: SimpleWebAuthnLogger;
    } = {},
  ): Promise<void> {
    // Reset server refreshes
    this.serverRefreshes = {};

    const {
      mdsServers = [defaultURLConvenienceMDS],
      payloads,
      logger = DefaultNoopLogger,
    } = opts;

    this.logger = buildLoggerAllMethods(logger);
    this.state = new ServiceStateTracker(this.serviceName, this.logger);
    this.metadataCache = new MDSCache<ProviderMetadata>();

    this.state.set(SERVICE_STATE.REFRESHING);

    /**
     * If passkey provider metadata is provided, load them into the cache first.
     */
    if (payloads?.length) {
      let entriesAdded = 0;

      payloads.forEach((payload) => {
        entriesAdded += this.cacheConvenienceMDS(NonRefreshingURL, payload);
      });

      this.logger.info(`Cached ${entriesAdded} local metadata entries`);
    }

    /**
     * If Convenience MDS server URLs are provided, then download and cache the current collection
     * of metadata from them.
     */
    if (mdsServers?.length) {
      // Get a current count so we know how many new entries we've added from C-MDS servers
      const currentCacheCount = this.metadataCache.count;
      // Track how many servers we were able to update
      let numServers = 0;

      for (const url of mdsServers) {
        this.metadataCache.registerMDSServer(url, 0, new Date(0));

        numServers += await this.refreshServer(url);
      }

      // Calculate the total number of new metadata entries we successfully added
      const newCacheCount = this.metadataCache.count;
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
    const _url = new URL(url);
    _url.searchParams.set('localCopySerial', String(no));
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
    this.metadataCache.clearMetadataByURL(url);

    // Cache entries
    Object.keys(payload).forEach((aaguid) => {
      // Skip the versioning property
      if (aaguid === 'no') {
        return;
      }

      // The rest of the keys will be AAGUIDs
      this.metadataCache.cacheMetadata(aaguid, payload[aaguid], url);
      entriesAdded += 1;
    });

    // Set up convenience metadata refresh
    this.metadataCache.registerMDSServer(
      url,
      payload.no,
      // Convenience MDS returns no nextUpdate, so pick a time in the future
      new Date(Date.now() + (1000 * 60 * 60 * this.cmdsDefaultRefreshDelayHours)),
    );

    return entriesAdded;
  }

  /**
   * Get a collection of metadata about a credential manager, including localized name(s) and
   * light and dark iconography when available. Returns `undefined` if no such metadata has been
   * registered with a Convenience MDS.
   */
  async getProviderMetadata(aaguid: string | Uint8Array_): Promise<ProviderMetadata | undefined> {
    if (this.state.current === SERVICE_STATE.DISABLED) {
      return;
    }

    // If a cache refresh is in progress then pause this until the service is ready
    await this.state.pauseUntilReady();

    // Refresh any servers whose data is stale, whether or not this AAGUID is cached. This lets
    // lookups of newly-registered AAGUIDs discover them
    await this.refreshStaleServers();

    const cachedMetadata = this.metadataCache.getMetadata(aaguid);

    return cachedMetadata;
  }

  /**
   * Refresh every server whose `nextUpdate` has passed
   */
  private async refreshStaleServers(): Promise<void> {
    const now = new Date();
    const staleURLs = this.metadataCache.getStaleMDSServerURLs(now);

    await Promise.all(staleURLs.map((url) => this.refreshServer(url)));
  }

  /**
   * Refresh a single server, joining the refresh already in flight if there is one. Refresh
   * failures cause that server's refresh to be re-attempted at a later date.
   */
  private serverRefreshes: { [url: string]: Promise<0 | 1> } = {};
  private refreshServer(url: string): Promise<0 | 1> {
    const inFlight = this.serverRefreshes[url];
    if (inFlight) {
      return inFlight;
    }

    this.state.set(SERVICE_STATE.REFRESHING);

    const refresh = (async () => {
      let numUpdated: 0 | 1 = 0;

      try {
        const mdsNo = this.metadataCache.getMDSServerDataVersion(url);
        const payload = await this.downloadConvenienceMDS(url, mdsNo);
        if (payload) {
          this.cacheConvenienceMDS(url, payload);
          numUpdated = 1;
        }
      } catch (err) {
        this.logger.error(`Could not download convenience metadata from "${url}":`, err);
        this.delayNextRefresh(url, this.cmdsDefaultRetryDelayHours);
        numUpdated = 0;
      } finally {
        delete this.serverRefreshes[url];
        // Only report ready once every refresh has finished
        if (Object.keys(this.serverRefreshes).length === 0) {
          this.state.set(SERVICE_STATE.READY);
        }
      }

      return numUpdated;
    })();

    this.serverRefreshes[url] = refresh;

    return refresh;
  }

  /**
   * Delay the next refresh attempt of this server by the specified number of hours
   */
  private delayNextRefresh(url: string, numHours: number): void {
    this.logger.debug(`Delaying next refresh of ${url} by ${numHours} hours`);
    const numHoursMS = 1000 * 60 * 60 * numHours;
    this.metadataCache.setMDSServerNextUpdate(url, new Date(Date.now() + numHoursMS));
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
