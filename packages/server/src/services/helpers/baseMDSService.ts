import { fetch } from '../../helpers/fetch.ts';
import {
  buildLoggerAllMethods,
  DefaultNoopLogger,
  type SimpleWebAuthnLogger,
} from '../../helpers/logging.ts';
import { getInitCacheMessage } from './getInitCacheMessage.ts';
import { MDSCache } from './mdsCache.ts';
import { SERVICE_STATE, ServiceStateTracker } from './serviceStateTracker.ts';

/**
 * Functionality shared by services that download, cache, and refresh metadata from FIDO
 * Alliance-style metadata servers (MDS and Convenience MDS.) Subclasses are responsible for
 * parsing and caching what a server returns.
 */
export abstract class BaseMDSService<MDSDataType> {
  protected readonly metadataCache = new MDSCache<MDSDataType>();
  protected state: ServiceStateTracker;
  protected logger: Required<SimpleWebAuthnLogger> = DefaultNoopLogger;

  /** How many hours to wait to check a server again when it has nothing new to download */
  protected readonly defaultRefreshDelayHours = 24;
  /** How many hours to wait to retry a _failed_ attempt to refresh a server */
  protected readonly defaultRetryDelayHours = 3;
  /** Abort downloads that take longer than this many milliseconds. No limit if left `undefined` */
  protected readonly downloadTimeoutMS = 10_000;

  /**
   * @param serviceName Used in logs, e.g. `"MetadataService"`
   * @param payloadLabel How download errors refer to what was downloaded, e.g. `"BLOB"`
   */
  constructor(
    protected readonly serviceName: string,
  ) {
    this.state = new ServiceStateTracker(serviceName, this.logger);
  }

  /**
   * Download from the server at `url` (if it has something newer than serial `no`) and cache the
   * result. Returns the number of entries cached, or `undefined` if nothing was cached (e.g. the
   * server had nothing new, or responded unsuccessfully.)
   */
  protected abstract downloadAndCache(url: string, no: number): Promise<number | undefined>;

  /**
   * Called when refreshing a server throws. Implementations can recover from the error (e.g. by
   * delaying the next refresh) or rethrow it so that lookups depending on the refresh fail.
   */
  protected abstract handleRefreshFailure(url: string, err: unknown): void;

  /**
   * Reset the service and move it to the `REFRESHING` state. Call this at the start of
   * `initialize()`.
   */
  protected beginInitialize(logger: SimpleWebAuthnLogger = DefaultNoopLogger): void {
    this.metadataCache.reset();
    this.serverRefreshes = {};

    this.logger = buildLoggerAllMethods(logger);
    this.state = new ServiceStateTracker(this.serviceName, this.logger);
    this.state.set(SERVICE_STATE.REFRESHING);
  }

  /**
   * Download and cache from each server. A server is only registered for refreshes once data from
   * it has been cached. One that can't be reached, or that doesn't respond with data, is skipped
   * so it can't cause lookups of other metadata to fail.
   *
   * Returns the number of servers entries were cached from.
   */
  protected async initializeServers(mdsServers?: string[]): Promise<number> {
    let numServers = 0;

    for (const url of mdsServers ?? []) {
      try {
        const entriesAdded = await this.downloadAndCache(url, 0);
        if (entriesAdded !== undefined) {
          numServers += 1;
          this.logger.debug(`Cached ${entriesAdded} metadata entries from "${url}"`);
        }
      } catch (err) {
        // Notify of the error and move on
        this.logger.error(`Could not download data from "${url}":`, err);
      }
    }

    return numServers;
  }

  /**
   * Log how much was cached and report the service as ready. Call this at the end of
   * `initialize()`.
   */
  protected finishInitialize(numLocalFiles?: number, numServers?: number): void {
    const cacheMessage = getInitCacheMessage(
      this.serviceName,
      this.metadataCache.count,
      numLocalFiles,
      numServers,
    );
    this.logger.info(cacheMessage);

    this.state.set(SERVICE_STATE.READY);
  }

  /**
   * Request data from a server, with a query param that can short-circuit the download if the
   * latest version is already cached. `no` is the serial number of the last data cached from this
   * server.
   *
   * Returns `undefined` if the server responded with anything other than data, in which case the
   * next refresh will have been delayed.
   *
   * See https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-mds-blob-proc-rules
   */
  protected async fetchFromServer(url: string, no: number): Promise<Response | undefined> {
    const _url = new URL(url);
    _url.searchParams.set('localCopySerial', String(no));
    const resp = await fetch(_url.toString(), {
      signal: AbortSignal.timeout(this.downloadTimeoutMS),
    });

    // We have the latest data, nothing more to do
    if (resp.status === 304) {
      await resp.body?.cancel();
      this.logger.info(
        `The MDS server at "${_url.toString()}" reported nothing new to download (HTTP 304)`,
      );
      // There's nothing new to download, wait another interval before checking again
      this.delayNextRefresh(url, this.defaultRefreshDelayHours);
      return;
    }

    // The FIDO MDS servers aggressively rate-limit so be prepared for that. We'll have to try again
    // later.
    if (resp.status === 429) {
      await resp.body?.cancel();
      this.logger.warn(
        `The MDS server at "${_url.toString()}" rate-limited this request (HTTP 429)`,
      );
      // We checked too soon, wait a bit before checking again
      this.delayNextRefresh(url, this.defaultRetryDelayHours);
      return;
    }

    if (!resp.ok) {
      await resp.body?.cancel();
      this.logger.warn(
        `The MDS server at "${_url.toString()}" reported an unsuccessful request (HTTP ${resp.status})`,
      );
      // Likely an HTTP 500 error, but anything not within HTTP 200-299. Wait a bit before trying
      // again
      this.delayNextRefresh(url, this.defaultRetryDelayHours);
      return;
    }

    return resp;
  }

  /**
   * Refresh every server whose `nextUpdate` has passed
   */
  protected async refreshStaleServers(): Promise<void> {
    const now = new Date();
    const staleURLs = this.metadataCache.getStaleMDSServerURLs(now);

    await Promise.all(staleURLs.map((url) => this.refreshServer(url)));
  }

  /**
   * Refresh a single server, subscribing to the refresh already in flight if there is one.
   * Failures are passed to `handleRefreshFailure()`.
   */
  private serverRefreshes: { [url: string]: Promise<void> } = {};
  private refreshServer(url: string): Promise<void> {
    const inFlight = this.serverRefreshes[url];
    if (inFlight) {
      return inFlight;
    }

    this.state.set(SERVICE_STATE.REFRESHING);

    const refresh = (async () => {
      try {
        const mdsNo = this.metadataCache.getMDSServerDataVersion(url);
        await this.downloadAndCache(url, mdsNo);
      } catch (err) {
        this.logger.error(`Could not download data from "${url}":`, err);
        this.handleRefreshFailure(url, err);
      } finally {
        delete this.serverRefreshes[url];
        // Only report ready once every refresh has finished
        if (Object.keys(this.serverRefreshes).length === 0) {
          this.state.set(SERVICE_STATE.READY);
        }
      }
    })();

    this.serverRefreshes[url] = refresh;

    return refresh;
  }

  /**
   * Delay the next refresh attempt of this server by the specified number of hours
   */
  protected delayNextRefresh(url: string, numHours: number): void {
    // Servers that haven't been cached from yet (i.e. still initializing) aren't refreshed so
    // there's no refresh to delay
    if (!this.metadataCache.mdsServerIsRegistered(url)) {
      return;
    }

    this.logger.debug(`Delaying next refresh of "${url}" by ${numHours} hours`);
    const numHoursMS = 1000 * 60 * 60 * numHours;
    this.metadataCache.setMDSServerNextUpdate(url, new Date(Date.now() + numHoursMS));
  }
}
