import { convertAAGUIDToString } from '../helpers/convertAAGUIDToString.ts';
import type { MetadataBLOBPayloadEntry, MetadataStatement } from '../metadata/mdsTypes.ts';
import { verifyMDSBlob } from '../metadata/verifyMDSBlob.ts';
import type { SimpleWebAuthnLogger } from '../helpers/logging.ts';
import type { Uint8Array_ } from '../types/index.ts';
import type { ProviderMetadata } from '../metadata/convenienceMDSTypes.ts';
import { SERVICE_STATE } from './helpers/serviceStateTracker.ts';
import { NonRefreshingURL } from './helpers/mdsCache.ts';
import { BaseMDSService } from './helpers/baseMDSService.ts';

const defaultURLMDS = 'https://mds.fidoalliance.org/'; // v3

/**
 * Allow MetadataService to accommodate unregistered AAGUIDs (`"permissive"`), or only allow
 * registered AAGUIDs (`"strict"`). Currently primarily impacts how `getStatement()` operates
 */
export type VerificationMode = 'permissive' | 'strict';

interface MetadataService {
  /**
   * Prepare the service to handle remote MDS servers and/or cache local metadata statements.
   *
   * **Options:**
   *
   * @param opts.mdsServers An array of URLs to FIDO Alliance Metadata Service
   * (version 3.0)-compatible servers. Defaults to the official FIDO MDS server
   * @param opts.statements An array of local metadata statements. Statements will be loaded but
   * not refreshed. When combined with `mdsServers`, a statement for the same AAGUID downloaded
   * from an MDS server will replace the local statement and get refreshed from then on
   * @param opts.verificationMode How MetadataService will handle unregistered AAGUIDs. Defaults to
   * `"strict"` which throws errors during registration response verification when an
   * unregistered AAGUID is encountered. Set to `"permissive"` to allow registration by
   * authenticators with unregistered AAGUIDs
   * @param opts.logger An instance of `SimpleWebAuthnLogger` that allows for capturing
   * MetadataService log output in a project-specific way
   */
  initialize(opts?: {
    mdsServers?: string[];
    statements?: MetadataStatement[];
    verificationMode?: VerificationMode;
    logger?: SimpleWebAuthnLogger;
  }): Promise<void>;
  /**
   * Get additional information about the authenticator associated with the given AAGUID.
   */
  getStatement(aaguid: string | Uint8Array): Promise<MetadataStatement | undefined>;
  /**
   * Get localized names and icons for the credential provider associated with the given AAGUID.
   */
  getProviderMetadata(aaguid: string | Uint8Array_): Promise<ProviderMetadata | undefined>;
}

/**
 * An implementation of `MetadataService` that can download and parse BLOBs, and support on-demand
 * requesting and caching of individual metadata statements.
 *
 * https://fidoalliance.org/metadata/
 */
export class BaseMetadataService extends BaseMDSService<MetadataBLOBPayloadEntry>
  implements MetadataService {
  private verificationMode: VerificationMode = 'strict';

  constructor() {
    super('MetadataService');
  }

  async initialize(
    opts: {
      mdsServers?: string[];
      statements?: MetadataStatement[];
      verificationMode?: VerificationMode;
      logger?: SimpleWebAuthnLogger;
    } = {},
  ): Promise<void> {
    const {
      mdsServers = [defaultURLMDS],
      statements,
      verificationMode,
      logger,
    } = opts;

    this.beginInitialize(logger);

    /**
     * If metadata statements are provided, load them into the cache first. These statements will
     * not be refreshed when a stale one is detected.
     */
    if (statements?.length) {
      let statementsAdded = 0;

      statements.forEach((statement) => {
        // Only cache statements that are for FIDO2-compatible authenticators
        statementsAdded += this.cacheMetadataBlobEntry(
          NonRefreshingURL,
          {
            aaguid: statement.aaguid,
            metadataStatement: statement,
            statusReports: [],
            timeOfLastStatusChange: '1970-01-01',
          },
        );
      });

      this.logger.info(`Cached ${statementsAdded} total local metadata statements`);
    }

    /**
     * If MDS servers are provided, then download blobs from them, verify them, and then add their
     * entries to the cache. Blobs loaded in this way will be refreshed when a stale entry within is
     * detected.
     */
    const numServers = await this.initializeServers(mdsServers);

    this.verificationMode = verificationMode ?? 'strict';

    this.finishInitialize(statements?.length, numServers);
  }

  async getStatement(aaguid: string | Uint8Array_): Promise<MetadataStatement | undefined> {
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

    // Refresh any servers whose BLOBs are stale, whether or not this AAGUID is cached. This lets
    // lookups of newly-registered AAGUIDs discover them
    await this.refreshStaleServers();

    // Try to grab a cached statement
    const entry = this.metadataCache.getMetadata(aaguid);

    if (!entry) {
      if (this.verificationMode === 'strict') {
        // FIDO conformance requires RP's to only support registered AAGUID's
        throw new Error(`No metadata statement found for aaguid "${aaguid}"`);
      }

      // Allow registration verification to continue without using metadata
      return;
    }

    // Check to see if the this aaguid has a status report with a "compromised" status
    for (const report of entry.statusReports) {
      const { status } = report;
      if (
        status === 'USER_VERIFICATION_BYPASS' ||
        status === 'ATTESTATION_KEY_COMPROMISE' ||
        status === 'USER_KEY_REMOTE_COMPROMISE' ||
        status === 'USER_KEY_PHYSICAL_COMPROMISE'
      ) {
        throw new Error(`Detected compromised aaguid "${aaguid}"`);
      }
    }

    return entry.metadataStatement;
  }

  async getProviderMetadata(aaguid: string | Uint8Array_): Promise<ProviderMetadata | undefined> {
    /**
     * This is a load-bearing check: without it the `this.verificationMode === 'strict'` check in
     * `getStatement()` will raise an error on this method when there's no need to do so because
     * this method's returning `undefined` does not impact the security posture of the RP.
     */
    if (!aaguid) {
      return;
    }

    // Try to grab a cached statement
    const metadataStatement = await this.getStatement(aaguid);

    if (!metadataStatement) {
      return;
    }

    return {
      friendlyNames: metadataStatement.friendlyNames,
      icon: metadataStatement.icon,
      iconDark: metadataStatement.iconDark,
      providerLogoDark: metadataStatement.providerLogoDark,
      providerLogoLight: metadataStatement.providerLogoLight,
    };
  }

  /**
   * Download the latest BLOB from MDS, verify it, and cache its entries
   */
  protected async downloadAndCache(url: string, no: number): Promise<number | undefined> {
    const resp = await this.fetchFromServer(url, no);
    if (!resp) {
      return;
    }

    // "BLOB" is FIDO's terminology, not mine
    const blob = await resp.text();
    return this.verifyBlob(blob, url, no);
  }

  /**
   * Refresh failures are rethrown so that lookups fail closed: until the refresh succeeds the
   * server stays stale, every lookup tries again, and none of them are answered with statements
   * from the BLOB that was previously cached.
   */
  protected handleRefreshFailure(_url: string, err: unknown): void {
    throw err;
  }

  /**
   * Verify and process the MDS metadata blob. Caches metadata and sets up refreshing when blobs
   * grow stale. `no` is the serial number of the last BLOB cached from this server.
   *
   * Returns the number of FIDO2 metadata statements that were cached.
   */
  private async verifyBlob(blob: string, url: string, no: number): Promise<number> {
    const { payload, parsedNextUpdate } = await verifyMDSBlob(blob);

    if (payload.no <= no) {
      // From FIDO MDS docs: "also ignore the file if its number (no) is less or equal to the
      // number of the last BLOB cached locally."
      throw new Error(
        `Latest BLOB no. ${payload.no} is not greater than previous no. ${no}`,
      );
    }

    // Remove statements from this server's previous BLOB so statements the server has since
    // dropped don't linger in the cache
    this.metadataCache.clearMetadataByURL(url);

    // Cache statements for FIDO2 devices
    let totalEntries = 0;
    for (const entry of payload.entries) {
      totalEntries += this.cacheMetadataBlobEntry(url, entry);
    }

    if (url !== NonRefreshingURL) {
      // Remember info about the server so we can refresh later
      this.metadataCache.registerMDSServer(
        url,
        // Store the payload `no` to make sure we're getting the next BLOB in the sequence
        payload.no,
        // Remember when we need to refresh this blob
        parsedNextUpdate,
      );
    } else {
      /**
       * This blob will not be refreshed, but we should still alert if the blob's `nextUpdate` is
       * in the past
       */
      if (parsedNextUpdate < new Date()) {
        // TODO (Feb 2026): It'd be more actionable for devs if a specific error was raised here,
        // then this message was logged higher up when it can include the array index of the stale
        // blob.
        this.logger.warn(
          `⚠️ This MDS blob (serial: ${payload.no}) contains stale data as of ${parsedNextUpdate.toISOString()}. Please consider re-initializing MetadataService with a newer MDS blob.`,
        );
      }
    }

    return totalEntries;
  }

  /**
   * A central place to contain logic and side effects of caching a BLOB entry. Only caches FIDO2
   * statements (i.e. ones with `aaguid` as UAF authenticators won't have one.) Returns `1` if the
   * statement was cached, or `0` if it wasn't (so you can `count += cacheMetadataBlobEntry(...)`)
   */
  private cacheMetadataBlobEntry(url: string, entry: MetadataBLOBPayloadEntry): number {
    // Only cache entries with an `aaguid`, which will weed out UAF statements
    if (!entry.aaguid) {
      return 0;
    }

    this.metadataCache.cacheMetadata(entry.aaguid, entry, url);

    return 1;
  }
}

/**
 * A basic service for coordinating interactions with the FIDO Metadata Service. This includes BLOB
 * download and parsing, and on-demand requesting and caching of individual metadata statements.
 *
 * https://fidoalliance.org/metadata/
 */
export const MetadataService: MetadataService = new BaseMetadataService();
