import type { DataURLPNGOrSVGString, DataURLSVGString, FriendlyNames } from './mdsTypes.ts';

/**
 * Passkey Provider metadata, including localized names, and light and dark mode icons.
 *
 * See https://fidoalliance.org/specs/mds/fido-convenience-metadata-service-v1.0-ps-20250521.html#sctn-convenience-details
 */
export type ProviderMetadata = {
  friendlyNames?: FriendlyNames;
  icon?: DataURLPNGOrSVGString;
  iconDark?: DataURLSVGString;
  providerLogoLight?: DataURLSVGString;
  providerLogoDark?: DataURLSVGString;
};

/**
 * A dictionary of payload data within a Convenience MDS blob. Except for the `"no"` property,
 * keys in this dictionary are AAGUIDs that map to `ProviderMetadata` dictionaries.
 *
 * Example:
 * ```json
 * {
 *   "no": 1,
 *   "12345678-1234-1234-1234-12345678": {...},
 *   "87654321-4321-4321-4321-87654321": {...}
 * }
 * ```
 *
 * See https://fidoalliance.org/specs/mds/fido-convenience-metadata-service-v1.0-ps-20250521.html#sctn-cmds-pe
 *
 * @property no - A serial number that increments whenever the convenience metadata payload is updated
 */
export type ConvenienceMDSPayload =
  & { no: number }
  & { [aaguid: string]: ProviderMetadata };
