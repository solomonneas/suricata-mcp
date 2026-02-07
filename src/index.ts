import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { getConfig } from "./config.js";
import { QueryEngine } from "./query/engine.js";
import { registerAlertTools } from "./tools/alerts.js";
import { registerFlowTools } from "./tools/flows.js";
import { registerDnsTools } from "./tools/dns.js";
import { registerHttpTools } from "./tools/http.js";
import { registerTlsTools } from "./tools/tls.js";
import { registerFileTools } from "./tools/files.js";
import { registerSshTools } from "./tools/ssh.js";
import { registerAnomalyTools } from "./tools/anomalies.js";
import { registerRuleTools } from "./tools/rules.js";
import { registerStatsTools } from "./tools/stats.js";
import { registerInvestigationTools } from "./tools/investigation.js";
import { registerBeaconingTools } from "./analytics/beaconing.js";
import { registerSocketTools } from "./socket/client.js";
import { registerResources } from "./resources.js";
import { registerPrompts } from "./prompts.js";

const server = new McpServer({
  name: "suricata-mcp",
  version: "1.0.0",
  description:
    "MCP server for Suricata IDS/IPS EVE JSON log analysis and rule management",
});

const config = getConfig();
const engine = new QueryEngine(config);

// Alert analysis
registerAlertTools(server, engine);

// Flow analysis
registerFlowTools(server, engine);
registerBeaconingTools(server, engine);

// Protocol analysis
registerDnsTools(server, engine);
registerHttpTools(server, engine);
registerTlsTools(server, engine);
registerSshTools(server, engine);

// File and anomaly analysis
registerFileTools(server, engine);
registerAnomalyTools(server, engine);

// Rule management
registerRuleTools(server, config);

// Engine stats
registerStatsTools(server, engine);

// Cross-type investigation
registerInvestigationTools(server, engine);

// Live commands via Unix socket
registerSocketTools(server, config);

// Resources and prompts
registerResources(server, engine, config);
registerPrompts(server);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
