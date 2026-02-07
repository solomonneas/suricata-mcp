import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { SuricataConfig } from "../config.js";
import { loadAllRules } from "../parser/rules.js";
import { matchesPartial } from "../query/filters.js";
import { aggregate } from "../query/aggregation.js";

export function registerRuleTools(
  server: McpServer,
  config: SuricataConfig,
): void {
  server.tool(
    "suricata_search_rules",
    "Search through Suricata rule files",
    {
      sid: z.number().optional().describe("Rule SID"),
      msg: z.string().optional().describe("Rule message (partial match)"),
      classtype: z.string().optional().describe("Rule classtype (partial match)"),
      reference: z.string().optional().describe("Rule reference (partial match)"),
      content: z.string().optional().describe("Rule content match (partial)"),
    },
    async (args) => {
      try {
        if (!config.rulesDir) {
          return {
            content: [{ type: "text" as const, text: "Rules directory not configured. Set SURICATA_RULES_DIR." }],
            isError: true,
          };
        }

        const allRules = await loadAllRules(config.rulesDir);
        const matched = allRules.filter((rule) => {
          if (args.sid !== undefined && rule.sid !== args.sid) return false;
          if (args.msg && rule.msg && !matchesPartial(rule.msg, args.msg)) return false;
          if (args.msg && !rule.msg) return false;
          if (args.classtype && rule.classtype && !matchesPartial(rule.classtype, args.classtype)) return false;
          if (args.classtype && !rule.classtype) return false;
          if (args.reference) {
            const hasRef = rule.reference?.some((r) => matchesPartial(r, args.reference!));
            if (!hasRef) return false;
          }
          if (args.content) {
            const hasContent = rule.content?.some((c) => matchesPartial(c, args.content!));
            if (!hasContent) return false;
          }
          return true;
        });

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({ count: matched.length, rules: matched }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error searching rules: ${error}` }],
          isError: true,
        };
      }
    },
  );

  server.tool(
    "suricata_rule_stats",
    "Get statistics about the loaded Suricata rule set",
    {},
    async () => {
      try {
        if (!config.rulesDir) {
          return {
            content: [{ type: "text" as const, text: "Rules directory not configured. Set SURICATA_RULES_DIR." }],
            isError: true,
          };
        }

        const allRules = await loadAllRules(config.rulesDir);
        const enabled = allRules.filter((r) => r.enabled);
        const disabled = allRules.filter((r) => !r.enabled);
        const byAction = aggregate(allRules.map((r) => r.action));
        const byClasstype = aggregate(
          allRules.filter((r) => r.classtype).map((r) => r.classtype!),
        );

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              totalRules: allRules.length,
              enabled: enabled.length,
              disabled: disabled.length,
              byAction,
              topClasstypes: byClasstype.slice(0, 20),
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error getting rule stats: ${error}` }],
          isError: true,
        };
      }
    },
  );
}
