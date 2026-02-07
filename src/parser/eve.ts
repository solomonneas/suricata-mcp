import { createReadStream } from "node:fs";
import { createInterface } from "node:readline";
import { createGunzip } from "node:zlib";
import { stat, readdir } from "node:fs/promises";
import { join } from "node:path";
import type { EveEvent, EventType, TimeRange } from "../types.js";

export interface ParseOptions {
  eventTypes?: EventType[];
  timeRange?: TimeRange;
  maxEvents?: number;
}

function isGzip(filePath: string): boolean {
  return filePath.endsWith(".gz");
}

function matchesTimeRange(
  timestamp: string,
  timeRange: TimeRange,
): boolean {
  if (timeRange.timeFrom && timestamp < timeRange.timeFrom) return false;
  if (timeRange.timeTo && timestamp > timeRange.timeTo) return false;
  return true;
}

export async function parseEveFile(
  filePath: string,
  options: ParseOptions = {},
): Promise<EveEvent[]> {
  const events: EveEvent[] = [];
  const max = options.maxEvents ?? Infinity;

  await streamEveFile(filePath, options, (event) => {
    if (events.length < max) {
      events.push(event);
      return events.length < max;
    }
    return false;
  });

  return events;
}

export async function streamEveFile(
  filePath: string,
  options: ParseOptions,
  callback: (event: EveEvent) => boolean | void,
): Promise<void> {
  const exists = await stat(filePath).catch(() => null);
  if (!exists) return;

  let stream: NodeJS.ReadableStream = createReadStream(filePath);
  if (isGzip(filePath)) {
    stream = stream.pipe(createGunzip());
  }

  const rl = createInterface({ input: stream, crlfDelay: Infinity });

  for await (const line of rl) {
    if (!line.trim()) continue;

    let parsed: EveEvent;
    try {
      parsed = JSON.parse(line);
    } catch {
      continue;
    }

    if (
      options.eventTypes &&
      !options.eventTypes.includes(parsed.event_type)
    ) {
      continue;
    }

    if (
      options.timeRange &&
      parsed.timestamp &&
      !matchesTimeRange(parsed.timestamp, options.timeRange)
    ) {
      continue;
    }

    const shouldContinue = callback(parsed);
    if (shouldContinue === false) {
      rl.close();
      break;
    }
  }
}

export async function findEveFiles(
  archiveDir: string,
  primaryFile: string,
): Promise<string[]> {
  const files: string[] = [];

  const primaryExists = await stat(primaryFile).catch(() => null);
  if (primaryExists) {
    files.push(primaryFile);
  }

  try {
    const dirEntries = await readdir(archiveDir);
    for (const entry of dirEntries) {
      const full = join(archiveDir, entry);
      if (full === primaryFile) continue;
      if (
        entry.startsWith("eve") &&
        (entry.endsWith(".json") || entry.endsWith(".json.gz"))
      ) {
        files.push(full);
      }
    }
  } catch {
    // Archive dir may not exist
  }

  return files.sort();
}

export async function parseEveFiles(
  files: string[],
  options: ParseOptions = {},
): Promise<EveEvent[]> {
  const allEvents: EveEvent[] = [];
  const max = options.maxEvents ?? Infinity;

  for (const file of files) {
    if (allEvents.length >= max) break;

    const remaining = max - allEvents.length;
    const events = await parseEveFile(file, {
      ...options,
      maxEvents: remaining,
    });
    allEvents.push(...events);
  }

  return allEvents;
}
