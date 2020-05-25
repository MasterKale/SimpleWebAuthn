import base64js from 'base64-js';

export default function toBase64String(buffer: ArrayBuffer): string {
  // TODO: Make sure converting buffer to Uint8Array() is correct
  return base64js.fromByteArray(new Uint8Array(buffer)).replace(/\+/g, '-').replace(/\//g, '_');
}
