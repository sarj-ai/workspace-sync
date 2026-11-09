export type LogEventMeta = Record<
  string,
  boolean | null | number | string | undefined
>;

export function logEvent(event: string, meta: LogEventMeta = {}): void {
  console.warn(serializeEvent(event, meta));
}

function serializeEvent(event: string, meta: LogEventMeta): string {
  return JSON.stringify({
    ...meta,
    evt: event,
    t: Date.now(),
  });
}
