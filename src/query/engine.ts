import type { SuricataConfig } from "../config.js";
import type { EveEvent, EventType, TimeRange } from "../types.js";
import { parseEveFile, findEveFiles, parseEveFiles } from "../parser/eve.js";

export interface QueryOptions {
  eventTypes: EventType[];
  timeRange?: TimeRange;
  maxResults: number;
}

export class QueryEngine {
  constructor(private config: SuricataConfig) {}

  async query<T extends EveEvent>(
    eventTypes: EventType[],
    filter: (event: T) => boolean,
    options?: {
      timeRange?: TimeRange;
      limit?: number;
    },
  ): Promise<T[]> {
    const maxResults = options?.limit ?? this.config.maxResults;
    const files = await findEveFiles(
      this.config.eveArchiveDir,
      this.config.evePath,
    );

    const events = await parseEveFiles(files, {
      eventTypes,
      timeRange: options?.timeRange,
      maxEvents: maxResults * 10,
    });

    const filtered: T[] = [];
    for (const event of events) {
      if (filter(event as T)) {
        filtered.push(event as T);
        if (filtered.length >= maxResults) break;
      }
    }

    return filtered;
  }

  async queryAll<T extends EveEvent>(
    eventTypes: EventType[],
    filter: (event: T) => boolean,
    options?: {
      timeRange?: TimeRange;
    },
  ): Promise<T[]> {
    const files = await findEveFiles(
      this.config.eveArchiveDir,
      this.config.evePath,
    );

    const events = await parseEveFiles(files, {
      eventTypes,
      timeRange: options?.timeRange,
    });

    return events.filter((e) => filter(e as T)) as T[];
  }
}
