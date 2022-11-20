import { toHash } from './toHash';
import { isoUint8Array } from './iso';

/**
 * Go through each expected RP ID and try to find one that matches. Raises an Error if no
 */
export async function matchExpectedRPID(
  rpIDHash: Uint8Array,
  expectedRPIDs: string[],
): Promise<void> {
  try {
    await Promise.any(
      expectedRPIDs.map(expected => {
        return new Promise((resolve, reject) => {
          toHash(isoUint8Array.fromASCIIString(expected)).then(expectedRPIDHash => {
            if (isoUint8Array.areEqual(rpIDHash, expectedRPIDHash)) {
              resolve(true);
            } else {
              reject();
            }
          });
        });
      }),
    );
  } catch (err) {
    const _err = err as Error;

    // This means no matches were found
    if (_err.name === 'AggregateError') {
      throw new UnexpectedRPIDHash();
    }

    // An unexpected error occurred
    throw err;
  }
}

class UnexpectedRPIDHash extends Error {
  constructor() {
    const message = 'Unexpected RP ID hash';
    super(message);
    this.name = 'UnexpectedRPIDHash';
  }
}
