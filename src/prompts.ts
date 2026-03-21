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
    "incident-response",
    "Full incident response workflow using Suricata alerts, Zeek enrichment, and TheHive case management",
    {
      alertSid: z.string().optional().describe("Suricata alert SID to investigate"),
      hostIp: z.string().optional().describe("Host IP to investigate"),
    },
    async (args) => {
      const startPart = args.alertSid
        ? `Start by investigating Suricata alert SID ${args.alertSid}.`
        : args.hostIp
          ? `Start by investigating host ${args.hostIp}.`
          : "Start by identifying the highest severity alerts with suricata_top_alerts.";

      return {
        messages: [
          {
            role: "user" as const,
            content: {
              type: "text" as const,
              text: [
                `Perform a full incident response investigation. ${startPart}`,
                "",
                "Follow this IR workflow:",
                "",
                "**Phase 1: Detection & Triage**",
                "1. Query Suricata alerts to understand the scope of the incident.",
                "2. Use suricata_investigate_host or suricata_investigate_alert for initial context.",
                "3. Check alert severity, category, and frequency to prioritize.",
                "",
                "**Phase 2: Zeek Enrichment**",
                "4. Use correlate_alert_with_zeek to get full network metadata for the alert.",
                "5. Check zeek_query_connections for the IP pair to see full connection history.",
                "6. Check zeek_query_dns for domain resolution context.",
                "7. Check zeek_query_ssl for TLS details and certificate information.",
                "8. Check zeek_query_files for any file transfers.",
                "",
                "**Phase 3: Threat Intel**",
                "9. Search MISP for known IOCs (IPs, domains, hashes) using misp_search_ioc.",
                "10. Check suricata_dga_detection for domain generation algorithm indicators.",
                "11. Run suricata_beaconing_detection for C2 communication patterns.",
                "12. Run suricata_exfiltration_detection for data theft indicators.",
                "",
                "**Phase 4: Case Management**",
                "13. Create a TheHive alert with thehive_create_alert including all observables.",
                "14. If confirmed incident, escalate to a case with thehive_create_case.",
                "",
                "**Phase 5: Containment Recommendations**",
                "15. Based on findings, recommend containment actions:",
                "    - Block malicious IPs/domains",
                "    - Isolate affected hosts",
                "    - Custom Suricata rules to detect variants",
                "    - Network-level mitigations",
              ].join("\n"),
            },
          },
        ],
      };
    },
  );

  server.prompt(
    "network-baseline",
    "Generate a network baseline report to establish normal traffic patterns",
    {
      timeWindow: z.string().optional().describe("Time window for baseline (e.g., '24h', '7d')"),
    },
    async (args) => {
      const timePart = args.timeWindow
        ? `Analyze traffic from the last ${args.timeWindow}.`
        : "Analyze traffic from the last 24 hours.";

      return {
        messages: [
          {
            role: "user" as const,
            content: {
              type: "text" as const,
              text: [
                `Generate a comprehensive network baseline report. ${timePart}`,
                "",
                "Include the following sections:",
                "",
                "1. **Traffic Volume**: Use suricata_flow_summary and zeek_connection_summary for total bytes, packets, and connection counts.",
                "2. **Top Talkers**: Identify the most active internal and external hosts.",
                "3. **Protocol Distribution**: Break down by protocol (TCP/UDP/ICMP) and application protocols.",
                "4. **Service Map**: What services are running internally? (ports, protocols)",
                "5. **DNS Baseline**: Top queried domains, query types, response codes from both Suricata and Zeek DNS logs.",
                "6. **TLS Landscape**: TLS versions in use, top certificate issuers, JA3 fingerprint distribution.",
                "7. **SSH Activity**: Internal SSH connections, client/server software versions.",
                "8. **Alert Baseline**: Normal alert volume, expected signatures (info-level vs actionable).",
                "9. **Anomaly Detection**: Run suricata_dga_detection, suricata_beaconing_detection, suricata_exfiltration_detection, and suricata_lateral_movement_detection.",
                "10. **Recommendations**: What looks normal vs what needs investigation.",
                "",
                "Format as a structured report suitable for a SOC team to use as a reference baseline.",
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
