import type { Interval } from "../types.js";

export interface TimeBucket {
  start: string;
  end: string;
  count: number;
  breakdown?: Record<string, number>;
}

function intervalToMs(interval: Interval): number {
  switch (interval) {
    case "1m":
      return 60 * 1000;
    case "5m":
      return 5 * 60 * 1000;
    case "15m":
      return 15 * 60 * 1000;
    case "1h":
      return 60 * 60 * 1000;
    case "1d":
      return 24 * 60 * 60 * 1000;
  }
}

function floorToInterval(timestamp: string, intervalMs: number): number {
  const ts = new Date(timestamp).getTime();
  return Math.floor(ts / intervalMs) * intervalMs;
}

export function bucketEvents<T extends { timestamp: string }>(
  events: T[],
  interval: Interval,
  breakdownFn?: (event: T) => string,
): TimeBucket[] {
  if (events.length === 0) return [];

  const intervalMs = intervalToMs(interval);
  const bucketMap = new Map<
    number,
    { count: number; breakdown: Map<string, number> }
  >();

  for (const event of events) {
    const bucketStart = floorToInterval(event.timestamp, intervalMs);

    let bucket = bucketMap.get(bucketStart);
    if (!bucket) {
      bucket = { count: 0, breakdown: new Map() };
      bucketMap.set(bucketStart, bucket);
    }

    bucket.count++;

    if (breakdownFn) {
      const key = breakdownFn(event);
      bucket.breakdown.set(key, (bucket.breakdown.get(key) ?? 0) + 1);
    }
  }

  const sortedKeys = Array.from(bucketMap.keys()).sort((a, b) => a - b);

  return sortedKeys.map((start) => {
    const bucket = bucketMap.get(start)!;
    const result: TimeBucket = {
      start: new Date(start).toISOString(),
      end: new Date(start + intervalMs).toISOString(),
      count: bucket.count,
    };

    if (breakdownFn && bucket.breakdown.size > 0) {
      result.breakdown = Object.fromEntries(bucket.breakdown);
    }

    return result;
  });
}
