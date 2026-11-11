export type LogEventMeta = Record<
  string,
  boolean | null | number | string | undefined
>;

export function logEvent(event: string, meta: LogEventMeta = {}): void {
  console.warn(
    JSON.stringify({
      ...meta,
      evt: event,
      t: Date.now(),
    }),
  );
}

export function logErrorEvent(event: string, meta: LogEventMeta = {}): void {
  console.error(JSON.stringify({ ...meta, evt: event, t: Date.now() }));
}
