import { toHash } from "./toHash.ts";
import { isoUint8Array } from "./iso/index.ts";

/**
 * Go through each expected RP ID and try to find one that matches. Returns the unhashed RP ID
 * that matched the hash in the response.
 *
 * Raises an `UnexpectedRPIDHash` error if no match is found
 */
export async function matchExpectedRPID(
  rpIDHash: Uint8Array,
  expectedRPIDs: string[],
): Promise<string> {
  try {
    const matchedRPID = await Promise.any<string>(
      expectedRPIDs.map((expected) => {
        return new Promise((resolve, reject) => {
          toHash(isoUint8Array.fromASCIIString(expected)).then(
            (expectedRPIDHash) => {
              if (isoUint8Array.areEqual(rpIDHash, expectedRPIDHash)) {
                resolve(expected);
              } else {
                reject();
              }
            },
          );
        });
      }),
    );

    return matchedRPID;
  } catch (err) {
    const _err = err as Error;

    // This means no matches were found
    if (_err.name === "AggregateError") {
      throw new UnexpectedRPIDHash();
    }

    // An unexpected error occurred
    throw err;
  }
}

class UnexpectedRPIDHash extends Error {
  constructor() {
    const message = "Unexpected RP ID hash";
    super(message);
    this.name = "UnexpectedRPIDHash";
  }
}
