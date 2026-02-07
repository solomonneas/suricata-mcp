import { readFile, readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import type { SuricataRule } from "../types.js";

function extractOption(body: string, key: string): string | undefined {
  const regex = new RegExp(`${key}\\s*:\\s*"([^"]*)"`, "g");
  const match = regex.exec(body);
  return match ? match[1] : undefined;
}

function extractAllOptions(body: string, key: string): string[] {
  const regex = new RegExp(`${key}\\s*:\\s*"([^"]*)"`, "g");
  const results: string[] = [];
  let match: RegExpExecArray | null;
  while ((match = regex.exec(body)) !== null) {
    results.push(match[1]);
  }
  return results;
}

function extractAllUnquoted(body: string, key: string): string[] {
  const regex = new RegExp(`${key}\\s*:\\s*([^;]+)`, "g");
  const results: string[] = [];
  let match: RegExpExecArray | null;
  while ((match = regex.exec(body)) !== null) {
    results.push(match[1].trim());
  }
  return results;
}

function extractSid(body: string): number {
  const match = /sid\s*:\s*(\d+)/.exec(body);
  return match ? parseInt(match[1], 10) : 0;
}

function extractRev(body: string): number | undefined {
  const match = /rev\s*:\s*(\d+)/.exec(body);
  return match ? parseInt(match[1], 10) : undefined;
}

function extractClasstype(body: string): string | undefined {
  const match = /classtype\s*:\s*([^;]+)/.exec(body);
  return match ? match[1].trim() : undefined;
}

export function parseRule(line: string): SuricataRule | null {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith("#") && !trimmed.match(/^#\s*(alert|drop|pass|reject)/)) {
    return null;
  }

  const enabled = !trimmed.startsWith("#");
  const ruleLine = enabled ? trimmed : trimmed.replace(/^#\s*/, "");

  const headerMatch = /^(alert|drop|pass|reject)\s+(\S+)\s+(\S+)\s+(\S+)\s+(->|<>)\s+(\S+)\s+(\S+)\s*\((.+)\)\s*$/.exec(ruleLine);
  if (!headerMatch) return null;

  const [, action, proto, srcNet, srcPort, direction, dstNet, dstPort, body] = headerMatch;

  return {
    raw: line,
    enabled,
    action,
    proto,
    srcNet,
    srcPort,
    direction,
    dstNet,
    dstPort,
    sid: extractSid(body),
    rev: extractRev(body),
    msg: extractOption(body, "msg"),
    classtype: extractClasstype(body),
    reference: extractAllUnquoted(body, "reference"),
    metadata: extractAllUnquoted(body, "metadata"),
    content: extractAllOptions(body, "content"),
  };
}

export async function parseRuleFile(filePath: string): Promise<SuricataRule[]> {
  const content = await readFile(filePath, "utf-8");
  const rules: SuricataRule[] = [];

  for (const line of content.split("\n")) {
    const rule = parseRule(line);
    if (rule) rules.push(rule);
  }

  return rules;
}

export async function loadAllRules(rulesDir: string): Promise<SuricataRule[]> {
  const allRules: SuricataRule[] = [];

  try {
    const entries = await readdir(rulesDir);
    for (const entry of entries) {
      if (!entry.endsWith(".rules")) continue;
      const fullPath = join(rulesDir, entry);
      const fileStat = await stat(fullPath);
      if (!fileStat.isFile()) continue;
      const rules = await parseRuleFile(fullPath);
      allRules.push(...rules);
    }
  } catch {
    // Rules directory may not exist
  }

  return allRules;
}
