export interface AggregationResult {
  key: string;
  count: number;
  percentage?: number;
}

export function aggregate(
  items: string[],
): AggregationResult[] {
  const counts = new Map<string, number>();
  for (const item of items) {
    counts.set(item, (counts.get(item) ?? 0) + 1);
  }

  const total = items.length;
  return Array.from(counts.entries())
    .map(([key, count]) => ({
      key,
      count,
      percentage: total > 0 ? Math.round((count / total) * 10000) / 100 : 0,
    }))
    .sort((a, b) => b.count - a.count);
}

export function topN(
  items: AggregationResult[],
  n: number,
): AggregationResult[] {
  return items.slice(0, n);
}

export function uniqueCount(items: string[]): number {
  return new Set(items).size;
}

export interface NumericStats {
  min: number;
  max: number;
  avg: number;
  sum: number;
  count: number;
  median: number;
}

export function numericStats(values: number[]): NumericStats {
  if (values.length === 0) {
    return { min: 0, max: 0, avg: 0, sum: 0, count: 0, median: 0 };
  }

  const sorted = [...values].sort((a, b) => a - b);
  const sum = sorted.reduce((a, b) => a + b, 0);
  const mid = Math.floor(sorted.length / 2);
  const median =
    sorted.length % 2 === 0
      ? (sorted[mid - 1] + sorted[mid]) / 2
      : sorted[mid];

  return {
    min: sorted[0],
    max: sorted[sorted.length - 1],
    avg: sum / sorted.length,
    sum,
    count: sorted.length,
    median,
  };
}
