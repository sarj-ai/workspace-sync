/*
 * Visits a bounded collection in source order.
 *
 * Use this only when each operation must observe the preceding operation's effects. Independent
 * work should use Promise.all or Promise.allSettled instead.
 */
export function forEachSequential<T>(
  items: readonly T[],
  visit: (item: T, index: number) => Promise<void>,
): Promise<void> {
  // eslint-disable-next-line typescript/no-invalid-void-type -- This shared visitor intentionally has a void accumulator and preserves Promise<void> scheduling.
  return reduceSequential<T, void>(items, undefined, (_previous, item, index) =>
    visit(item, index),
  );
}

/* Maps provider work in source order without overlapping requests. */
export async function mapSequential<T, Result>(
  items: readonly T[],
  visit: (item: T, index: number) => Promise<Result>,
): Promise<Result[]> {
  const results: Result[] = [];
  await forEachSequential(items, async (item, index) => {
    results.push(await visit(item, index));
  });
  return results;
}

/* Folds provider work in source order without overlapping requests. */
export function reduceSequential<T, Accumulator>(
  items: readonly T[],
  initial: Accumulator,
  visit: (
    accumulator: Accumulator,
    item: T,
    index: number,
  ) => Promise<Accumulator>,
): Promise<Accumulator> {
  return items.reduce<Promise<Accumulator>>(
    async (previous, item, index) => visit(await previous, item, index),
    Promise.resolve(initial),
  );
}

export function chunk<T>(
  items: readonly T[],
  size: number,
): readonly (readonly T[])[] {
  if (!Number.isSafeInteger(size) || size < 1)
    throw new RangeError("Chunk size must be positive");
  return Array.from({ length: Math.ceil(items.length / size) }, (_, index) =>
    items.slice(index * size, (index + 1) * size),
  );
}
