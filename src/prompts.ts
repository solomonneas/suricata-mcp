import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

export function registerPrompts(server: McpServer): void {
  server.prompt(
    "investigate-alert",
    "Alert investigation workflow - query the alert, find related flows, check protocol details",
    {
      signatureId: z.string().optional().describe("Suricata rule SID to investigate"),
      srcIp: z.string().optional().describe("Source IP to filter by"),
    },
    async (args) => {
      const sidPart = args.signatureId
        ? `Start by querying alerts with signature ID ${args.signatureId}.`
        : "Start by identifying the alert you want to investigate using suricata_top_alerts or suricata_query_alerts.";

      const srcPart = args.srcIp
        ? ` Focus on source IP ${args.srcIp}.`
        : "";

      return {
        messages: [
          {
            role: "user" as const,
            content: {
              type: "text" as const,
              text: [
                "Investigate a Suricata alert following this workflow:",
                "",
                `1. ${sidPart}${srcPart}`,
                "2. Use suricata_investigate_alert to get the full alert context with correlated flows.",
                "3. Check related DNS activity for the source/destination IPs.",
                "4. Look at HTTP and TLS traffic for the same IP pair.",
                "5. Check for any file transfers associated with these IPs.",
                "6. Look at the flow summary to understand the bandwidth and connection patterns.",
                "7. Search the rule set with suricata_search_rules to understand what the rule detects.",
                "8. Assess the severity and recommend a response:",
                "   - Is this a true positive or likely false positive?",
                "   - What is the potential impact?",
                "   - What containment/remediation steps should be taken?",
              ].join("\n"),
            },
          },
        ],
      };
    },
  );

  server.prompt(
    "hunt-for-threats",
    "Proactive threat hunting across Suricata data",
    {
      timeWindow: z.string().optional().describe("Time window to hunt in (e.g., '24h', '7d')"),
      focus: z.string().optional().describe("Specific focus area (e.g., 'beaconing', 'exfiltration', 'lateral')"),
    },
    async (args) => {
      const timePart = args.timeWindow
        ? `Focus on the last ${args.timeWindow}.`
        : "Focus on the last 24 hours.";

      const focusPart = args.focus
        ? ` Pay special attention to ${args.focus} indicators.`
        : "";

      return {
        messages: [
          {
            role: "user" as const,
            content: {
              type: "text" as const,
              text: [
                `Perform a proactive threat hunt across Suricata data. ${timePart}${focusPart}`,
                "",
                "Follow this threat hunting methodology:",
                "",
                "1. **Alert Triage**: Use suricata_top_alerts to identify high-severity and high-frequency alerts.",
                "2. **Beaconing Detection**: Run suricata_beaconing_detection to find periodic C2-like connections.",
                "3. **Suspicious TLS**: Query TLS connections and check JA3/JA4 fingerprints against known malware.",
                "4. **DNS Anomalies**: Look for unusual DNS patterns (high entropy domains, many NXDOMAIN responses).",
                "5. **Protocol Anomalies**: Check suricata_query_anomalies for protocol violations.",
                "6. **Large Transfers**: Search flows with high byte counts that could indicate data exfiltration.",
                "7. **Unusual Ports**: Look for application protocols on non-standard ports.",
                "8. **SSH Activity**: Check for new or unusual SSH connections.",
                "",
                "For each finding, assess the risk and provide actionable recommendations.",
              ].join("\n"),
            },
          },
        ],
      };
    },
  );

  server.prompt(
    "daily-alert-report",
    "Generate a daily alert summary report",
    {
      date: z.string().optional().describe("Date for the report (ISO 8601, defaults to today)"),
    },
    async (args) => {
      const datePart = args.date
        ? `Generate a daily alert report for ${args.date}.`
        : "Generate a daily alert report for today.";

      return {
        messages: [
          {
            role: "user" as const,
            content: {
              type: "text" as const,
              text: [
                datePart,
                "",
                "Include the following sections:",
                "",
                "1. **Executive Summary**: Total alerts, severity breakdown, IDS vs IPS action counts.",
                "2. **Top Signatures**: Use suricata_top_alerts - list the top 10 most frequent signatures with counts.",
                "3. **Top Sources**: Most active source IPs triggering alerts.",
                "4. **Top Destinations**: Most targeted destination IPs.",
                "5. **Alert Timeline**: Use suricata_alert_timeline with 1h intervals to show activity patterns.",
                "6. **New Signatures**: Any signatures seen for the first time today.",
                "7. **Severity Trends**: Compare today's severity distribution with the alert summary.",
                "8. **Recommendations**: Based on the data, what should analysts prioritize?",
                "",
                "Format the report in clear, structured markdown suitable for a SOC daily briefing.",
              ].join("\n"),
            },
          },
        ],
      };
    },
  );
}
