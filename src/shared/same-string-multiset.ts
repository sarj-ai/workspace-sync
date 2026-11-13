export function sameStringMultiset(
  left: readonly string[],
  right: readonly string[],
): boolean {
  if (left.length !== right.length) return false;
  const sortedRight = right.toSorted();
  return left.toSorted().every((value, index) => value === sortedRight[index]);
}
