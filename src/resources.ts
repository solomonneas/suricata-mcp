import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { QueryEngine } from "./query/engine.js";
import type { SuricataConfig } from "./config.js";
import type { StatsEvent } from "./types.js";
import { loadAllRules } from "./parser/rules.js";
import { aggregate } from "./query/aggregation.js";

export function registerResources(
  server: McpServer,
  engine: QueryEngine,
  config: SuricataConfig,
): void {
  server.resource(
    "event-types",
    "suricata://event-types",
    async () => {
      const eventTypes = [
        { type: "alert", description: "IDS/IPS alert triggered by a rule match", keyFields: "signature_id, signature, severity, category, action, src_ip, dest_ip" },
        { type: "flow", description: "Network flow records with byte/packet counts", keyFields: "src_ip, dest_ip, proto, app_proto, bytes_toserver, bytes_toclient, state" },
        { type: "dns", description: "DNS transactions with query/response details", keyFields: "rrname, rrtype, rdata, rcode" },
        { type: "http", description: "HTTP transactions with full request/response metadata", keyFields: "hostname, url, http_method, status, http_user_agent" },
        { type: "tls", description: "TLS handshake information with JA3/JA4 fingerprints", keyFields: "sni, version, subject, issuer, ja3, ja4" },
        { type: "fileinfo", description: "File extraction metadata with hashes", keyFields: "filename, magic, md5, sha256, size" },
        { type: "smtp", description: "SMTP transaction details", keyFields: "mail_from, rcpt_to, helo" },
        { type: "ssh", description: "SSH protocol version information", keyFields: "client.software_version, server.software_version" },
        { type: "anomaly", description: "Protocol anomalies and malformed packets", keyFields: "type, event, layer" },
        { type: "stats", description: "Engine performance and capture statistics", keyFields: "capture, decoder, detect, flow" },
        { type: "drop", description: "Dropped packets in IPS mode", keyFields: "alert fields + drop reason" },
      ];

      return {
        contents: [{
          uri: "suricata://event-types",
          mimeType: "application/json",
          text: JSON.stringify(eventTypes, null, 2),
        }],
      };
    },
  );

  server.resource(
    "stats-current",
    "suricata://stats/current",
    async () => {
      try {
        const stats = await engine.query<StatsEvent>(
          ["stats"],
          () => true,
          { limit: 1 },
        );

        const latest = stats.length > 0 ? stats[stats.length - 1] : null;

        return {
          contents: [{
            uri: "suricata://stats/current",
            mimeType: "application/json",
            text: JSON.stringify(latest ? latest.stats : { message: "No stats available" }, null, 2),
          }],
        };
      } catch {
        return {
          contents: [{
            uri: "suricata://stats/current",
            mimeType: "application/json",
            text: JSON.stringify({ error: "Failed to read stats" }),
          }],
        };
      }
    },
  );

  server.resource(
    "rules-summary",
    "suricata://rules/summary",
    async () => {
      try {
        if (!config.rulesDir) {
          return {
            contents: [{
              uri: "suricata://rules/summary",
              mimeType: "application/json",
              text: JSON.stringify({ message: "Rules directory not configured" }),
            }],
          };
        }

        const rules = await loadAllRules(config.rulesDir);
        const enabled = rules.filter((r) => r.enabled).length;
        const byAction = aggregate(rules.map((r) => r.action));

        return {
          contents: [{
            uri: "suricata://rules/summary",
            mimeType: "application/json",
            text: JSON.stringify({
              totalRules: rules.length,
              enabled,
              disabled: rules.length - enabled,
              byAction,
            }, null, 2),
          }],
        };
      } catch {
        return {
          contents: [{
            uri: "suricata://rules/summary",
            mimeType: "application/json",
            text: JSON.stringify({ error: "Failed to read rules" }),
          }],
        };
      }
    },
  );
}
