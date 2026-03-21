import { createReadStream } from "node:fs";
import { createInterface } from "node:readline";
import { stat, readdir } from "node:fs/promises";
import { join } from "node:path";

export interface ZeekRecord {
  [key: string]: string;
}

export interface ZeekLogMeta {
  separator: string;
  setSeparator: string;
  emptyField: string;
  unsetField: string;
  path: string;
  fields: string[];
  types: string[];
}

function parseSeparator(raw: string): string {
  return raw.replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) =>
    String.fromCharCode(parseInt(hex, 16)),
  );
}

export function parseZeekHeader(lines: string[]): ZeekLogMeta {
  const meta: ZeekLogMeta = {
    separator: "\t",
    setSeparator: ",",
    emptyField: "(empty)",
    unsetField: "-",
    path: "",
    fields: [],
    types: [],
  };

  for (const line of lines) {
    if (!line.startsWith("#")) break;
    if (line.startsWith("#separator")) {
      meta.separator = parseSeparator(line.split(" ").slice(1).join(" ").trim());
    } else if (line.startsWith("#set_separator")) {
      meta.setSeparator = line.split(meta.separator)[1] ?? ",";
    } else if (line.startsWith("#empty_field")) {
      meta.emptyField = line.split(meta.separator)[1] ?? "(empty)";
    } else if (line.startsWith("#unset_field")) {
      meta.unsetField = line.split(meta.separator)[1] ?? "-";
    } else if (line.startsWith("#path")) {
      meta.path = line.split(meta.separator)[1] ?? "";
    } else if (line.startsWith("#fields")) {
      meta.fields = line.split(meta.separator).slice(1);
    } else if (line.startsWith("#types")) {
      meta.types = line.split(meta.separator).slice(1);
    }
  }

  return meta;
}

export function parseZeekLine(
  line: string,
  meta: ZeekLogMeta,
): ZeekRecord | null {
  if (line.startsWith("#") || !line.trim()) return null;

  const parts = line.split(meta.separator);
  const record: ZeekRecord = {};

  for (let i = 0; i < meta.fields.length && i < parts.length; i++) {
    const value = parts[i];
    if (value === meta.unsetField || value === meta.emptyField) {
      record[meta.fields[i]] = "";
    } else {
      record[meta.fields[i]] = value;
    }
  }

  return record;
}

export interface ZeekParseOptions {
  filter?: (record: ZeekRecord) => boolean;
  maxRecords?: number;
}

export async function parseZeekFile(
  filePath: string,
  options: ZeekParseOptions = {},
): Promise<{ meta: ZeekLogMeta; records: ZeekRecord[] }> {
  const exists = await stat(filePath).catch(() => null);
  if (!exists) return { meta: parseZeekHeader([]), records: [] };

  const stream = createReadStream(filePath);
  const rl = createInterface({ input: stream, crlfDelay: Infinity });

  const headerLines: string[] = [];
  const records: ZeekRecord[] = [];
  let meta: ZeekLogMeta | null = null;
  const max = options.maxRecords ?? Infinity;

  for await (const line of rl) {
    if (line.startsWith("#")) {
      headerLines.push(line);
      continue;
    }

    if (!meta) {
      meta = parseZeekHeader(headerLines);
    }

    if (records.length >= max) {
      rl.close();
      break;
    }

    const record = parseZeekLine(line, meta);
    if (!record) continue;

    if (options.filter && !options.filter(record)) continue;

    records.push(record);
  }

  if (!meta) {
    meta = parseZeekHeader(headerLines);
  }

  return { meta, records };
}

export async function findZeekLog(
  zeekLogsDir: string,
  logName: string,
): Promise<string | null> {
  try {
    const entries = await readdir(zeekLogsDir);
    if (entries.includes(logName)) {
      return join(zeekLogsDir, logName);
    }
    const currentDir = join(zeekLogsDir, "current");
    const currentExists = await stat(currentDir).catch(() => null);
    if (currentExists) {
      const currentEntries = await readdir(currentDir);
      if (currentEntries.includes(logName)) {
        return join(currentDir, logName);
      }
    }
    return null;
  } catch {
    return null;
  }
}

export function zeekTsToIso(ts: string): string {
  const num = parseFloat(ts);
  if (isNaN(num)) return "";
  return new Date(num * 1000).toISOString();
}
