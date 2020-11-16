import cbor from 'cbor';

export function decodeCborFirst(input: string | Buffer | ArrayBufferView): any {
  try {
    // throws if there are extra bytes
    return cbor.decodeFirstSync(input);
  } catch (err) {
    // if the error was due to extra bytes, return the unpacked value
    if (err.value) {
      return err.value;
    }
    throw err;
  }
}
