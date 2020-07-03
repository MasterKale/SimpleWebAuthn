import { Base64URLString } from '@simplewebauthn/typescript-types';
import fetch from 'node-fetch';

import { ENV_VARS } from '../helpers/constants';
import toHash from '../helpers/toHash';
import validateCertificatePath from '../helpers/validateCertificatePath';
import convertASN1toPEM from '../helpers/convertASN1toPEM';

import parseJWT from './parseJWT';

const { ENABLE_MDS, MDS_TOC_URL, MDS_API_TOKEN, MDS_ROOT_CERT_URL } = ENV_VARS;

type CachedAAGUID = {
  url: string;
  hash: string;
  statement?: MetadataStatement;
};

/**
 * A basic service to coordinate interactions with the FIDO Metadata Service. This includes TOC
 * download and parsing, and on-demand requesting and caching of individual metadata statements.
 *
 * https://fidoalliance.org/metadata/
 */
class MetadataService {
  private cache: { [aaguid: string]: CachedAAGUID } = {};
  private nextUpdate: Date = new Date(0);
  private tocAlg = '';
  private tocNo = 0;

  /**
   * Prepare the service to handle live data, or prepared data.
   *
   * If `process.env.ENABLE_MDS` is `'true'`, then the actual MDS API will be queried. Otherwise
   * known metadata statements can be provided as arguments.
   */
  async initialize(statements?: MetadataStatement[]): Promise<void> {
    if (ENABLE_MDS) {
      await this.downloadTOC();
    } else {
      if (statements?.length) {
        statements.forEach(statement => {
          this.cache[statement.aaguid] = { url: '', hash: '', statement };
        });
      }
    }
  }

  /**
   * Get a metadata statement for a given aaguid. Defaults to returning a cached statement.
   *
   * If `process.env.ENABLE_MDS` is `'true'`, then this method will coordinate re-downloading data
   * as per the `nextUpdate` property in the initial TOC download.
   */
  async getStatement(aaguid: string): Promise<MetadataStatement | undefined> {
    if (!aaguid) {
      return;
    }

    if (ENABLE_MDS) {
      const now = new Date();
      if (now > this.nextUpdate) {
        await this.downloadTOC();
      }
    }

    const cached = this.cache[aaguid];

    if (!cached) {
      return;
    }

    if (!cached.statement && ENABLE_MDS) {
      // Download the metadata statement if it's not been cached
      const resp = await fetch(`${cached.url}?token=${MDS_API_TOKEN}`);
      const data = await resp.text();
      const statement: MetadataStatement = JSON.parse(
        Buffer.from(data, 'base64').toString('ascii'),
      );

      const hashAlg = this.tocAlg === 'ES256' ? 'SHA256' : undefined;
      const calculatedHash = toHash(data, hashAlg).toString('base64');

      if (calculatedHash === cached.hash) {
        // Update the cached entry with the latest statement
        cached.statement = statement;
      } else {
        // From FIDO MDS docs: "Ignore the downloaded metadata statement if the hash value doesn't
        // match."
        cached.statement = undefined;
      }
    }

    return cached.statement;
  }

  /**
   * Download and process the latest TOC from MDS
   */
  private async downloadTOC() {
    // Query MDS for the latest TOC
    const respTOC = await fetch(`${MDS_TOC_URL}?token=${MDS_API_TOKEN}`);
    const data = await respTOC.text();

    // Break apart the JWT we get back
    const parsedJWT = parseJWT<MDSJWTTOCHeader, MDSJWTTOCPayload>(data);
    const header = parsedJWT[0];
    const payload = parsedJWT[1];

    if (payload.no <= this.tocNo) {
      // From FIDO MDS docs: "also ignore the file if its number (no) is less or equal to the
      // number of the last Metadata TOC object cached locally."
      return;
    }

    // Download FIDO the root certificate and append it to the TOC certs
    const respFIDORootCert = await fetch(MDS_ROOT_CERT_URL);
    const fidoRootCert = await respFIDORootCert.text();
    const fullCertPath = header.x5c.map(convertASN1toPEM).concat(fidoRootCert);

    try {
      // Validate the certificate chain
      validateCertificatePath(fullCertPath);
    } catch (err) {
      console.error(err);
      // From FIDO MDS docs: "The FIDO Server SHOULD ignore the file if the signature is invalid."
      return;
    }

    // Convert the nextUpdate property into a Date so we can determine when to redownload
    const [year, month, day] = payload.nextUpdate.split('-');
    this.nextUpdate = new Date(
      parseInt(year, 10),
      // Months need to be zero-indexed
      parseInt(month, 10) - 1,
      parseInt(day, 10),
    );

    // Store the header `alg` so we know what to use when verifying metadata statement hashes
    this.tocAlg = header.alg;

    // Store the payload `no` to make sure we're getting the next TOC in the sequence
    this.tocNo = payload.no;

    // Prepare the in-memory cache of statements.
    for (const entry of payload.entries) {
      // Only cache entries with an `aaguid`
      if (entry.aaguid) {
        const _entry = entry as TOCAAGUIDEntry;
        const cached: CachedAAGUID = {
          url: entry.url,
          hash: entry.hash,
        };

        this.cache[_entry.aaguid] = cached;
      }
    }
  }
}

const metadataService = new MetadataService();

export default metadataService;

type MetadataStatement = {
  aaguid: string;
  assertionScheme: string;
  attachmentHint: number;
  attestationRootCertificates: Base64URLString[];
  attestationTypes: number[];
  authenticationAlgorithm: number;
  authenticatorVersion: number;
  description: string;
  icon: string;
  isSecondFactorOnly: string;
  keyProtection: number;
  legalHeader: string;
  matcherProtection: number;
  protocolFamily: string;
  publicKeyAlgAndEncoding: number;
  tcDisplay: number;
  tcDisplayContentType: string;
  upv: [{ major: number; minor: number }];
  userVerificationDetails: [[{ userVerification: 1 }]];
};

type MDSJWTTOCHeader = {
  alg: string;
  typ: string;
  x5c: Base64URLString[];
};

type MDSJWTTOCPayload = {
  // YYYY-MM-DD
  nextUpdate: string;
  entries: TOCEntry[];
  no: number;
  legalHeader: string;
};

type TOCEntry = {
  url: string;
  // YYYY-MM-DD
  timeOfLastStatusChange: string;
  hash: string;
  aaid?: string;
  aaguid?: string;
  attestationCertificateKeyIdentifiers: string[];
  statusReports: {
    status: string;
    certificateNumber: string;
    certificate: string;
    certificationDescriptor: string;
    url: string;
    certificationRequirementsVersion: string;
    certificationPolicyVersion: string;
    // YYYY-MM-DD
    effectiveDate: string;
  }[];
};

type TOCAAGUIDEntry = Omit<TOCEntry, 'aaid'> & {
  aaguid: string;
};
