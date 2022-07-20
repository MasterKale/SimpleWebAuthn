import cbor from 'cbor';

/**
 * Convert an extension data buffer to a proper object
 *
 * @param extensionDataBuffer Extension Data buffer
 */
export default function decodeExtensionDataBuffer(extensionDataBuffer: Buffer): ExtensionsJSON {
  const toCBOR: ExtensionsJSON = cbor.decodeAllSync(extensionDataBuffer)[0];
  return toCBOR;
}

export type ExtensionsJSON = {
  devicePublicKey?: DevicePublicKeyJSON
}

export type DevicePublicKeyJSON = {
  dpk?: Buffer;
  scp?: Buffer;
  sig?: string;
  aaguid?: Buffer;
}
