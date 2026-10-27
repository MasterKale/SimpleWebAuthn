import type { SimpleWebAuthnLogger } from '../helpers/logging.ts';
import type { ConvenienceMDSPayload, ProviderMetadata } from '../metadata/convenienceMDSTypes.ts';
import type { Uint8Array_ } from '../types/index.ts';
import { NonRefreshingURL } from './helpers/mdsCache.ts';
import { SERVICE_STATE } from './helpers/serviceStateTracker.ts';
import { BaseMDSService } from './helpers/baseMDSService.ts';

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
   * Localized names
   *
   * Example:
   * ```ts
   * await ConvenenienceMetadataService.getProviderMetadata('531126d6-e717-415c-9320-3d9aa6981239');
   * ```
   * Returns:
   * ```json
   * {
   *   "friendlyNames": { "en-US": "Dashlane" },
   *   "providerLogoLight": "data:image/svg+xml;base64,...",
   *   "providerLogoDark": "data:image/svg+xml;base64,..."
   * }
   * ```
   */
  getProviderMetadata(aaguid: string | Uint8Array_): Promise<ProviderMetadata | undefined>;
}

export class BaseConvenienceMetadataService extends BaseMDSService<ProviderMetadata>
  implements ConvenienceMetadataService {
  constructor() {
    super('ConvenienceMetadataService');
  }

  async initialize(
    opts: {
      mdsServers?: string[];
      payloads?: ConvenienceMDSPayload[];
      logger?: SimpleWebAuthnLogger;
    } = {},
  ): Promise<void> {
    const {
      mdsServers = [defaultURLConvenienceMDS],
      payloads,
      logger,
    } = opts;

    this.beginInitialize(logger);

    /**
     * If passkey provider metadata is provided, load them into the cache first.
     */
    if (payloads?.length) {
      let entriesAdded = 0;

      payloads.forEach((payload) => {
        entriesAdded += this.cacheConvenienceMDS(NonRefreshingURL, payload);
      });

      this.logger.debug(`Cached ${entriesAdded} total local metadata entries`);
    }

    /**
     * If Convenience MDS server URLs are provided, then download and cache the current collection
     * of metadata from them.
     */
    const numServers = await this.initializeServers(mdsServers);

    this.finishInitialize(payloads?.length, numServers);
  }

  /**
   * Download the convenience metadata, which is surprisingly just a JSON document, and cache it
   */
  protected async downloadAndCache(url: string, no: number): Promise<number | undefined> {
    const resp = await this.fetchFromServer(url, no);
    if (!resp) {
      return;
    }

    const payload: ConvenienceMDSPayload = await resp.json();
    return this.cacheConvenienceMDS(url, payload);
  }

  /**
   * Refresh failures cause that server's refresh to be re-attempted at a later date
   */
  protected handleRefreshFailure(url: string): void {
    this.delayNextRefresh(url, this.defaultRetryDelayHours);
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
      new Date(Date.now() + (1000 * 60 * 60 * this.defaultRefreshDelayHours)),
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
}

/**
 * A basic service for coordinating interactions with the FIDO Convenience Metadata Service. This
 * includes metadata download and parsing, and on-demand requesting and caching of provider details.
 *
 * https://fidoalliance.org/metadata/
 */
export const ConvenienceMetadataService: ConvenienceMetadataService =
  new BaseConvenienceMetadataService();
