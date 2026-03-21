import { describe, it, expect, beforeAll } from "vitest";
import { resolve } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SuricataConfig } from "../src/config.js";
import { QueryEngine } from "../src/query/engine.js";
import { registerCorrelationTools } from "../src/tools/correlation.js";

const TEST_DATA_DIR = resolve(import.meta.dirname, "../test-data");

function createTestConfig(): SuricataConfig {
  return {
    evePath: resolve(TEST_DATA_DIR, "eve.json"),
    eveArchiveDir: TEST_DATA_DIR,
    rulesDir: TEST_DATA_DIR,
    maxResults: 1000,
    unixSocket: null,
    zeekLogsDir: TEST_DATA_DIR,
    pcapDir: null,
    mispUrl: null,
    mispApiKey: null,
    thehiveUrl: null,
    thehiveApiKey: null,
  };
}

type ToolHandler = (args: Record<string, unknown>) => Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }>;

function captureTools(server: McpServer): Map<string, ToolHandler> {
  const tools = new Map<string, ToolHandler>();
  const origTool = server.tool.bind(server);
  server.tool = ((...args: unknown[]) => {
    const name = args[0] as string;
    const handler = args[args.length - 1] as ToolHandler;
    tools.set(name, handler);
    return origTool(...(args as Parameters<typeof origTool>));
  }) as typeof server.tool;
  return tools;
}

function parseResult(result: { content: Array<{ type: string; text: string }> }) {
  return JSON.parse(result.content[0].text);
}

describe("Cross-Correlation Tools", () => {
  let tools: Map<string, ToolHandler>;

  beforeAll(() => {
    const config = createTestConfig();
    const engine = new QueryEngine(config);
    const server = new McpServer({ name: "test", version: "1.0.0" });
    tools = captureTools(server);
    registerCorrelationTools(server, engine, config);
  });

  it("should register the correlation tool", () => {
    expect(tools.has("correlate_alert_with_zeek")).toBe(true);
  });

  it("should correlate alerts with Zeek data by SID", async () => {
    const result = await tools.get("correlate_alert_with_zeek")!({
      signatureId: 2024001,
      windowSeconds: 600,
    });
    const data = parseResult(result);
    expect(data.alertsCorrelated).toBeGreaterThan(0);
    expect(data.correlations).toBeDefined();
    expect(data.correlations.length).toBeGreaterThan(0);

    const corr = data.correlations[0];
    expect(corr.alert).toBeDefined();
    expect(corr.alert.signatureId).toBe(2024001);
    expect(corr.zeek).toBeDefined();
  });

  it("should correlate alerts by source IP", async () => {
    const result = await tools.get("correlate_alert_with_zeek")!({
      srcIp: "192.168.1.100",
      windowSeconds: 600,
    });
    const data = parseResult(result);
    expect(data.alertsCorrelated).toBeGreaterThan(0);
  });

  it("should return no results for non-matching SID", async () => {
    const result = await tools.get("correlate_alert_with_zeek")!({
      signatureId: 9999999,
    });
    const data = parseResult(result);
    expect(data.message).toBe("No matching alerts found");
  });

  it("should handle missing Zeek config", async () => {
    const noZeekConfig: SuricataConfig = { ...createTestConfig(), zeekLogsDir: null };
    const engine2 = new QueryEngine(noZeekConfig);
    const server2 = new McpServer({ name: "test", version: "1.0.0" });
    const tools2 = captureTools(server2);
    registerCorrelationTools(server2, engine2, noZeekConfig);
    const result = await tools2.get("correlate_alert_with_zeek")!({ signatureId: 2024001 });
    expect(result.isError).toBe(true);
  });
});
