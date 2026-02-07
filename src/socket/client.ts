import { createConnection } from "node:net";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { SuricataConfig } from "../config.js";

function sendCommand(
  socketPath: string,
  command: string,
  args?: Record<string, string>,
): Promise<string> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (fn: () => void) => {
      if (!settled) {
        settled = true;
        fn();
      }
    };

    const socket = createConnection(socketPath, () => {
      // Suricata Unix socket protocol requires version negotiation first
      socket.write(JSON.stringify({ version: "0.2" }));
    });

    let phase: "version" | "command" = "version";
    let data = "";

    socket.on("data", (chunk) => {
      data += chunk.toString();

      // Try to parse accumulated data as JSON
      try {
        const parsed = JSON.parse(data);

        if (phase === "version") {
          // Version ack received, now send the actual command
          phase = "command";
          data = "";
          const cmd = args
            ? JSON.stringify({ command, arguments: args })
            : JSON.stringify({ command });
          socket.write(cmd);
        } else {
          // Command response received, close and resolve
          socket.destroy();
          finish(() => resolve(JSON.stringify(parsed)));
        }
      } catch {
        // Incomplete JSON, keep accumulating
      }
    });

    socket.on("end", () => {
      finish(() => resolve(data));
    });

    socket.on("error", (err) => {
      finish(() => reject(new Error(`Socket error: ${err.message}`)));
    });

    socket.setTimeout(10000, () => {
      socket.destroy();
      finish(() => reject(new Error("Socket command timed out")));
    });
  });
}

export function registerSocketTools(
  server: McpServer,
  config: SuricataConfig,
): void {
  server.tool(
    "suricata_reload_rules",
    "Trigger a live rule reload via Suricata Unix socket",
    {},
    async () => {
      try {
        if (!config.unixSocket) {
          return {
            content: [{ type: "text" as const, text: "Unix socket not configured. Set SURICATA_UNIX_SOCKET." }],
            isError: true,
          };
        }

        const result = await sendCommand(config.unixSocket, "reload-rules");
        return {
          content: [{ type: "text" as const, text: JSON.stringify({ status: "success", response: result }, null, 2) }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error reloading rules: ${error}` }],
          isError: true,
        };
      }
    },
  );

  server.tool(
    "suricata_iface_stat",
    "Get interface capture statistics from Suricata",
    {
      iface: z.string().optional().describe("Interface name (e.g., eth0)"),
    },
    async (args) => {
      try {
        if (!config.unixSocket) {
          return {
            content: [{ type: "text" as const, text: "Unix socket not configured. Set SURICATA_UNIX_SOCKET." }],
            isError: true,
          };
        }

        const cmdArgs = args.iface ? { iface: args.iface } : undefined;
        const result = await sendCommand(config.unixSocket, "iface-stat", cmdArgs);
        return {
          content: [{ type: "text" as const, text: JSON.stringify({ status: "success", response: result }, null, 2) }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error getting interface stats: ${error}` }],
          isError: true,
        };
      }
    },
  );
}
