import { describe, it, expect, beforeAll } from "vitest";
import { resolve } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SuricataConfig } from "../src/config.js";
import { parseZeekFile, parseZeekHeader, parseZeekLine, type ZeekLogMeta } from "../src/parser/zeek.js";
import { registerZeekTools } from "../src/tools/zeek.js";

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

describe("Zeek Parser", () => {
  it("should parse Zeek log header", () => {
    const lines = [
      "#separator \\x09",
      "#set_separator\t,",
      "#empty_field\t(empty)",
      "#unset_field\t-",
      "#path\tconn",
      "#fields\tts\tuid\tid.orig_h\tid.orig_p",
      "#types\ttime\tstring\taddr\tport",
    ];
    const meta = parseZeekHeader(lines);
    expect(meta.separator).toBe("\t");
    expect(meta.path).toBe("conn");
    expect(meta.fields).toEqual(["ts", "uid", "id.orig_h", "id.orig_p"]);
    expect(meta.types).toEqual(["time", "string", "addr", "port"]);
  });

  it("should parse a Zeek TSV line", () => {
    const meta: ZeekLogMeta = {
      separator: "\t",
      setSeparator: ",",
      emptyField: "(empty)",
      unsetField: "-",
      path: "conn",
      fields: ["ts", "uid", "id.orig_h", "id.orig_p"],
      types: ["time", "string", "addr", "port"],
    };
    const record = parseZeekLine("1736935200.000000\tCaBC123\t192.168.1.100\t54321", meta);
    expect(record).not.toBeNull();
    expect(record!["ts"]).toBe("1736935200.000000");
    expect(record!["id.orig_h"]).toBe("192.168.1.100");
    expect(record!["id.orig_p"]).toBe("54321");
  });

  it("should handle unset fields as empty string", () => {
    const meta: ZeekLogMeta = {
      separator: "\t",
      setSeparator: ",",
      emptyField: "(empty)",
      unsetField: "-",
      path: "test",
      fields: ["a", "b", "c"],
      types: ["string", "string", "string"],
    };
    const record = parseZeekLine("hello\t-\t(empty)", meta);
    expect(record!["a"]).toBe("hello");
    expect(record!["b"]).toBe("");
    expect(record!["c"]).toBe("");
  });

  it("should skip comment lines", () => {
    const meta: ZeekLogMeta = {
      separator: "\t",
      setSeparator: ",",
      emptyField: "(empty)",
      unsetField: "-",
      path: "test",
      fields: ["a"],
      types: ["string"],
    };
    const record = parseZeekLine("#close\t2025-01-15", meta);
    expect(record).toBeNull();
  });

  it("should parse conn.log file", async () => {
    const { meta, records } = await parseZeekFile(resolve(TEST_DATA_DIR, "conn.log"));
    expect(meta.path).toBe("conn");
    expect(meta.fields).toContain("id.orig_h");
    expect(records.length).toBe(12);
  });

  it("should parse dns.log file", async () => {
    const { meta, records } = await parseZeekFile(resolve(TEST_DATA_DIR, "dns.log"));
    expect(meta.path).toBe("dns");
    expect(records.length).toBe(8);
  });

  it("should filter records during parse", async () => {
    const { records } = await parseZeekFile(resolve(TEST_DATA_DIR, "conn.log"), {
      filter: (r) => r["proto"] === "udp",
    });
    expect(records.length).toBe(1);
    expect(records[0]["id.orig_h"]).toBe("192.168.1.50");
  });

  it("should respect maxRecords limit", async () => {
    const { records } = await parseZeekFile(resolve(TEST_DATA_DIR, "conn.log"), {
      maxRecords: 3,
    });
    expect(records.length).toBe(3);
  });

  it("should return empty for non-existent file", async () => {
    const { records } = await parseZeekFile("/nonexistent/path/conn.log");
    expect(records).toEqual([]);
  });
});

describe("Zeek Tools", () => {
  let tools: Map<string, ToolHandler>;

  beforeAll(() => {
    const config = createTestConfig();
    const server = new McpServer({ name: "test", version: "1.0.0" });
    tools = captureTools(server);
    registerZeekTools(server, config);
  });

  it("should register all Zeek tools", () => {
    expect(tools.has("zeek_query_connections")).toBe(true);
    expect(tools.has("zeek_query_dns")).toBe(true);
    expect(tools.has("zeek_query_http")).toBe(true);
    expect(tools.has("zeek_query_ssl")).toBe(true);
    expect(tools.has("zeek_query_files")).toBe(true);
    expect(tools.has("zeek_query_ssh")).toBe(true);
    expect(tools.has("zeek_query_weird")).toBe(true);
    expect(tools.has("zeek_connection_summary")).toBe(true);
  });

  it("should query all connections", async () => {
    const result = await tools.get("zeek_query_connections")!({});
    const data = parseResult(result);
    expect(data.count).toBe(12);
  });

  it("should filter connections by source IP", async () => {
    const result = await tools.get("zeek_query_connections")!({ srcIp: "192.168.1.100" });
    const data = parseResult(result);
    expect(data.count).toBeGreaterThan(0);
    for (const conn of data.connections) {
      expect(conn["id.orig_h"]).toBe("192.168.1.100");
    }
  });

  it("should filter connections by protocol", async () => {
    const result = await tools.get("zeek_query_connections")!({ proto: "udp" });
    const data = parseResult(result);
    expect(data.count).toBe(1);
  });

  it("should filter connections by service", async () => {
    const result = await tools.get("zeek_query_connections")!({ service: "ssh" });
    const data = parseResult(result);
    expect(data.count).toBe(1);
  });

  it("should filter connections by minimum bytes", async () => {
    const result = await tools.get("zeek_query_connections")!({ minBytes: 100000 });
    const data = parseResult(result);
    expect(data.count).toBeGreaterThan(0);
  });

  it("should generate connection summary", async () => {
    const result = await tools.get("zeek_connection_summary")!({});
    const data = parseResult(result);
    expect(data.totalConnections).toBe(12);
    expect(data.topSources.length).toBeGreaterThan(0);
    expect(data.protocolDistribution.length).toBeGreaterThan(0);
  });

  it("should query DNS logs", async () => {
    const result = await tools.get("zeek_query_dns")!({});
    const data = parseResult(result);
    expect(data.count).toBe(8);
  });

  it("should filter DNS by query name", async () => {
    const result = await tools.get("zeek_query_dns")!({ query: "evil" });
    const data = parseResult(result);
    expect(data.count).toBeGreaterThan(0);
  });

  it("should filter DNS by rcode", async () => {
    const result = await tools.get("zeek_query_dns")!({ rcode: "NXDOMAIN" });
    const data = parseResult(result);
    expect(data.count).toBe(3);
  });

  it("should query HTTP logs", async () => {
    const result = await tools.get("zeek_query_http")!({});
    const data = parseResult(result);
    expect(data.count).toBe(4);
  });

  it("should filter HTTP by host", async () => {
    const result = await tools.get("zeek_query_http")!({ host: "malware" });
    const data = parseResult(result);
    expect(data.count).toBe(2);
  });

  it("should filter HTTP by method", async () => {
    const result = await tools.get("zeek_query_http")!({ method: "POST" });
    const data = parseResult(result);
    expect(data.count).toBe(1);
  });

  it("should query SSL logs", async () => {
    const result = await tools.get("zeek_query_ssl")!({});
    const data = parseResult(result);
    expect(data.count).toBe(3);
  });

  it("should filter SSL by server name", async () => {
    const result = await tools.get("zeek_query_ssl")!({ serverName: "suspicious" });
    const data = parseResult(result);
    expect(data.count).toBe(2);
  });

  it("should query files logs", async () => {
    const result = await tools.get("zeek_query_files")!({});
    const data = parseResult(result);
    expect(data.count).toBe(3);
  });

  it("should filter files by mime type", async () => {
    const result = await tools.get("zeek_query_files")!({ mimeType: "octet-stream" });
    const data = parseResult(result);
    expect(data.count).toBe(1);
  });

  it("should query SSH logs", async () => {
    const result = await tools.get("zeek_query_ssh")!({});
    const data = parseResult(result);
    expect(data.count).toBe(2);
  });

  it("should filter SSH by auth success", async () => {
    const result = await tools.get("zeek_query_ssh")!({ authSuccess: true });
    const data = parseResult(result);
    expect(data.count).toBe(1);
  });

  it("should filter SSH by client software", async () => {
    const result = await tools.get("zeek_query_ssh")!({ client: "PuTTY" });
    const data = parseResult(result);
    expect(data.count).toBe(1);
  });

  it("should query weird logs", async () => {
    const result = await tools.get("zeek_query_weird")!({});
    const data = parseResult(result);
    expect(data.count).toBe(4);
  });

  it("should filter weird by name", async () => {
    const result = await tools.get("zeek_query_weird")!({ name: "checksum" });
    const data = parseResult(result);
    expect(data.count).toBe(1);
  });

  it("should handle missing Zeek config gracefully", async () => {
    const noZeekConfig: SuricataConfig = { ...createTestConfig(), zeekLogsDir: null };
    const server2 = new McpServer({ name: "test", version: "1.0.0" });
    const tools2 = captureTools(server2);
    registerZeekTools(server2, noZeekConfig);
    const result = await tools2.get("zeek_query_connections")!({});
    expect(result.isError).toBe(true);
  });
});
