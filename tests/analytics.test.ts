import { describe, it, expect, beforeAll } from "vitest";
import { resolve } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SuricataConfig } from "../src/config.js";
import { QueryEngine } from "../src/query/engine.js";
import { shannonEntropy, extractDomainBase, registerDgaDetectionTools } from "../src/analytics/dns_entropy.js";
import { registerExfiltrationTools } from "../src/analytics/exfiltration.js";
import { isRfc1918, registerLateralMovementTools } from "../src/analytics/lateral.js";

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

describe("Shannon Entropy", () => {
  it("should calculate entropy for a simple string", () => {
    const e = shannonEntropy("aaaa");
    expect(e).toBe(0); // all same character
  });

  it("should have higher entropy for random strings", () => {
    const low = shannonEntropy("aaaa");
    const high = shannonEntropy("abcdefghij");
    expect(high).toBeGreaterThan(low);
  });

  it("should handle empty string", () => {
    expect(shannonEntropy("")).toBe(0);
  });

  it("should flag DGA-like domains with high entropy", () => {
    const normal = shannonEntropy("google");
    const dga = shannonEntropy("xk7qm2r9p4v6w");
    expect(dga).toBeGreaterThan(normal);
    expect(dga).toBeGreaterThan(3.0);
  });
});

describe("Domain Base Extraction", () => {
  it("should extract the longest label minus TLD", () => {
    expect(extractDomainBase("evil-domain.xyz")).toBe("evil-domain");
  });

  it("should handle subdomains", () => {
    expect(extractDomainBase("sub.evil-domain.xyz")).toBe("evil-domain");
  });

  it("should handle single label", () => {
    expect(extractDomainBase("localhost")).toBe("localhost");
  });
});

describe("RFC1918 Detection", () => {
  it("should identify 10.x.x.x as RFC1918", () => {
    expect(isRfc1918("10.0.0.1")).toBe(true);
    expect(isRfc1918("10.255.255.255")).toBe(true);
  });

  it("should identify 172.16-31.x.x as RFC1918", () => {
    expect(isRfc1918("172.16.0.1")).toBe(true);
    expect(isRfc1918("172.31.255.255")).toBe(true);
    expect(isRfc1918("172.32.0.1")).toBe(false);
  });

  it("should identify 192.168.x.x as RFC1918", () => {
    expect(isRfc1918("192.168.1.1")).toBe(true);
    expect(isRfc1918("192.168.255.255")).toBe(true);
  });

  it("should reject public IPs", () => {
    expect(isRfc1918("8.8.8.8")).toBe(false);
    expect(isRfc1918("93.184.216.34")).toBe(false);
  });

  it("should handle invalid IPs", () => {
    expect(isRfc1918("not-an-ip")).toBe(false);
  });
});

describe("DGA Detection Tool", () => {
  let tools: Map<string, ToolHandler>;

  beforeAll(() => {
    const config = createTestConfig();
    const engine = new QueryEngine(config);
    const server = new McpServer({ name: "test", version: "1.0.0" });
    tools = captureTools(server);
    registerDgaDetectionTools(server, engine);
  });

  it("should register the DGA detection tool", () => {
    expect(tools.has("suricata_dga_detection")).toBe(true);
  });

  it("should detect DGA-like domains in test data", async () => {
    const result = await tools.get("suricata_dga_detection")!({ entropyThreshold: 2.5 });
    const data = parseResult(result);
    expect(data.totalDnsQueries).toBeGreaterThan(0);
    // Our test data has some high-entropy domain names
  });
});

describe("Exfiltration Detection Tool", () => {
  let tools: Map<string, ToolHandler>;

  beforeAll(() => {
    const config = createTestConfig();
    const engine = new QueryEngine(config);
    const server = new McpServer({ name: "test", version: "1.0.0" });
    tools = captureTools(server);
    registerExfiltrationTools(server, engine);
  });

  it("should register the exfiltration detection tool", () => {
    expect(tools.has("suricata_exfiltration_detection")).toBe(true);
  });

  it("should run without errors", async () => {
    const result = await tools.get("suricata_exfiltration_detection")!({
      minBytesOut: 1000,
      minRatio: 1.0,
    });
    const data = parseResult(result);
    expect(data.totalFlowsAnalyzed).toBeDefined();
    expect(data.exfiltrationCandidates).toBeDefined();
  });
});

describe("Lateral Movement Detection Tool", () => {
  let tools: Map<string, ToolHandler>;

  beforeAll(() => {
    const config = createTestConfig();
    const engine = new QueryEngine(config);
    const server = new McpServer({ name: "test", version: "1.0.0" });
    tools = captureTools(server);
    registerLateralMovementTools(server, engine);
  });

  it("should register the lateral movement detection tool", () => {
    expect(tools.has("suricata_lateral_movement_detection")).toBe(true);
  });

  it("should run without errors", async () => {
    const result = await tools.get("suricata_lateral_movement_detection")!({
      minTargets: 1,
      includeCommonPorts: true,
    });
    const data = parseResult(result);
    expect(data.totalInternalFlows).toBeDefined();
    expect(data.lateralCandidates).toBeDefined();
  });
});
