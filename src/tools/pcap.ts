import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { exec as execCb } from "node:child_process";
import { readdir, stat } from "node:fs/promises";
import { join, basename } from "node:path";
import { promisify } from "node:util";
import type { SuricataConfig } from "../config.js";

const execAsync = promisify(execCb);

function sanitizeFilename(name: string): string {
  // Only allow alphanumeric, dash, underscore, dot
  return basename(name).replace(/[^a-zA-Z0-9._-]/g, "");
}

export function registerPcapTools(
  server: McpServer,
  config: SuricataConfig,
): void {
  server.tool(
    "pcap_list",
    "List available PCAP files in the drop directory",
    {},
    async () => {
      try {
        if (!config.pcapDir) {
          return { content: [{ type: "text" as const, text: "PCAP directory not configured. Set PCAP_DIR." }], isError: true };
        }
        const entries = await readdir(config.pcapDir);
        const pcaps: Array<{ name: string; size: number; modified: string }> = [];

        for (const entry of entries) {
          if (!entry.endsWith(".pcap") && !entry.endsWith(".pcapng") && !entry.endsWith(".cap")) continue;
          const fullPath = join(config.pcapDir, entry);
          const s = await stat(fullPath).catch(() => null);
          if (s && s.isFile()) {
            pcaps.push({
              name: entry,
              size: s.size,
              modified: s.mtime.toISOString(),
            });
          }
        }

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({ count: pcaps.length, pcaps }, null, 2),
          }],
        };
      } catch (error) {
        return { content: [{ type: "text" as const, text: `Error listing PCAPs: ${error}` }], isError: true };
      }
    },
  );

  server.tool(
    "pcap_replay_suricata",
    "Replay a PCAP file through Suricata for analysis",
    {
      filename: z.string().describe("PCAP filename (must exist in PCAP directory)"),
    },
    async (args) => {
      try {
        if (!config.pcapDir) {
          return { content: [{ type: "text" as const, text: "PCAP directory not configured. Set PCAP_DIR." }], isError: true };
        }
        const safe = sanitizeFilename(args.filename);
        if (!safe) {
          return { content: [{ type: "text" as const, text: "Invalid filename." }], isError: true };
        }

        const fullPath = join(config.pcapDir, safe);
        const exists = await stat(fullPath).catch(() => null);
        if (!exists) {
          return { content: [{ type: "text" as const, text: `PCAP file not found: ${safe}` }], isError: true };
        }

        const cmd = `docker exec suricata suricata -r /pcaps/${safe} -l /var/log/suricata/`;
        const { stdout, stderr } = await execAsync(cmd, { timeout: 120000 });

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              status: "completed",
              filename: safe,
              stdout: stdout.trim(),
              stderr: stderr.trim(),
            }, null, 2),
          }],
        };
      } catch (error) {
        return { content: [{ type: "text" as const, text: `Error replaying PCAP through Suricata: ${error}` }], isError: true };
      }
    },
  );

  server.tool(
    "pcap_replay_zeek",
    "Replay a PCAP file through Zeek for analysis",
    {
      filename: z.string().describe("PCAP filename (must exist in PCAP directory)"),
    },
    async (args) => {
      try {
        if (!config.pcapDir) {
          return { content: [{ type: "text" as const, text: "PCAP directory not configured. Set PCAP_DIR." }], isError: true };
        }
        const safe = sanitizeFilename(args.filename);
        if (!safe) {
          return { content: [{ type: "text" as const, text: "Invalid filename." }], isError: true };
        }

        const fullPath = join(config.pcapDir, safe);
        const exists = await stat(fullPath).catch(() => null);
        if (!exists) {
          return { content: [{ type: "text" as const, text: `PCAP file not found: ${safe}` }], isError: true };
        }

        const cmd = `docker exec zeek /usr/local/zeek/bin/zeek -r /pcaps/${safe}`;
        const { stdout, stderr } = await execAsync(cmd, { timeout: 120000 });

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              status: "completed",
              filename: safe,
              stdout: stdout.trim(),
              stderr: stderr.trim(),
            }, null, 2),
          }],
        };
      } catch (error) {
        return { content: [{ type: "text" as const, text: `Error replaying PCAP through Zeek: ${error}` }], isError: true };
      }
    },
  );
}
