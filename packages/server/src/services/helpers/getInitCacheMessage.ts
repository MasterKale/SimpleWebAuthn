/**
 * Generate a message detailing how many metadata entries were cached, and from which sources
 *
 * Examples:
 *
 * - "ConvenienceMetadataService cached 322 unique metadata entries from 1 local payload(s) and 1 convenience metadata server(s)"
 * - "ConvenienceMetadataService cached 322 unique metadata entries from 1 local payload(s)"
 * - "MetadataService cached 285 unique metadata entries from 1 convenience metadata server(s)"
 * - "MetadataService cached 0 unique metadata entries"
 */
export function getInitCacheMessage(
  serviceName: string,
  cacheCount: number,
  numLocalFiles?: number,
  numServers?: number,
): string {
  let message = `${serviceName} cached ${cacheCount} unique entries`;

  if (cacheCount) {
    const formatter = new Intl.ListFormat('en', {
      style: 'long',
      type: 'conjunction',
    });
    const sources = [];
    if (numLocalFiles) {
      sources.push(`${numLocalFiles} local file(s)`);
    }
    if (numServers) {
      sources.push(`${numServers} metadata server(s)`);
    }

    message = `${message} from ${formatter.format(sources)}`;
  }

  return message;
}
