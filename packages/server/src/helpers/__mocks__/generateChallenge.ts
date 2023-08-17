export function generateChallenge(): Promise<Uint8Array> {
  return new Promise((resolve) => {
    resolve(Uint8Array.from([
      1,
      2,
      3,
      4,
      5,
      6,
      7,
      8,
      9,
      10,
      11,
      12,
      13,
      14,
      15,
      16,
    ]));
  });
}
