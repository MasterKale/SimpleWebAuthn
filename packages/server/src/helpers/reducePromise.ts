export default async function reducePromise<K, T>(
  arr: K[],
  fn: (acc: T, el: K) => T | Promise<T>,
  acc: T,
  index = 0,
): Promise<T> {
  if (arr[index]) {
    const newAcc = await Promise.resolve(fn(acc, arr[index]));
    return reducePromise(arr, fn, newAcc, index + 1);
  }
  return acc;
}
