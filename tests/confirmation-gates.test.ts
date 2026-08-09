import { describe, it, expect } from "vitest";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SuricataConfig } from "../src/config.js";
import { checkMutationAllowed } from "../src/tools/mutation.js";
import { registerRuleTools } from "../src/tools/rules.js";
import { registerPcapTools } from "../src/tools/pcap.js";

const TEST_DATA_DIR = resolve(import.meta.dirname, "../test-data");

type ToolHandler = (args: Record<string, unknown>) => Promise<{
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
}>;

function createTestConfig(overrides: Partial<SuricataConfig> = {}): SuricataConfig {
  return {
    evePath: resolve(TEST_DATA_DIR, "eve.json"),
    eveArchiveDir: TEST_DATA_DIR,
    rulesDir: TEST_DATA_DIR,
    maxResults: 1000,
    unixSocket: null,
    zeekLogsDir: null,
    pcapDir: null,
    mispUrl: null,
    mispApiKey: null,
    thehiveUrl: null,
    thehiveApiKey: null,
    allowMutation: false,
    ...overrides,
  };
}

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

function registerGatedTool(
  toolName: string,
  config: SuricataConfig,
): Map<string, ToolHandler> {
  const server = new McpServer({ name: "test", version: "1.0.0" });
  const tools = captureTools(server);

  if (toolName.startsWith("suricata_")) {
    registerRuleTools(server, config);
  } else if (toolName.startsWith("pcap_")) {
    registerPcapTools(server, config);
  } else {
    throw new Error(`Unknown gated tool: ${toolName}`);
  }

  return tools;
}

/** Every destructive tool that requires confirm:true plus SURICATA_ALLOW_MUTATION=1. */
const GATED_TOOLS = [
  "suricata_create_rule",
  "suricata_toggle_rule",
  "suricata_reload_rules_docker",
  "pcap_replay_suricata",
  "pcap_replay_zeek",
] as const;

type GatedToolName = (typeof GATED_TOOLS)[number];

const UNCONFIRMED_ARGS: Record<GatedToolName, Record<string, unknown>> = {
  suricata_create_rule: {
    rule: 'alert tcp any any -> any any (msg:"gate"; sid:1000100; rev:1;)',
  },
  suricata_toggle_rule: { sid: 1000100, enable: false },
  suricata_reload_rules_docker: {},
  pcap_replay_suricata: { filename: "sample.pcap" },
  pcap_replay_zeek: { filename: "sample.pcap" },
};

function confirmedArgs(toolName: GatedToolName): Record<string, unknown> {
  return { ...UNCONFIRMED_ARGS[toolName], confirm: true };
}

function expectConfirmGateError(text: string): void {
  expect(text).toContain("destructive operation");
  expect(text).toContain("confirm: true");
}

function expectMutationDisabledError(text: string): void {
  expect(text).toContain("mutating tools are disabled");
  expect(text).toContain("SURICATA_ALLOW_MUTATION");
}

describe("checkMutationAllowed", () => {
  it("refuses when mutation is disabled even with confirm:true", () => {
    const gate = checkMutationAllowed(
      createTestConfig({ allowMutation: false }),
      { confirm: true },
      "test action",
    );
    expect(gate.allowed).toBe(false);
    if (gate.allowed) return;
    expect(gate.response.isError).toBe(true);
    expect(gate.response.content[0].text).toMatch(/Refusing to test action/);
    expectMutationDisabledError(gate.response.content[0].text);
  });

  it("refuses when confirm is omitted", () => {
    const gate = checkMutationAllowed(
      createTestConfig({ allowMutation: true }),
      {},
      "test action",
    );
    expect(gate.allowed).toBe(false);
    if (gate.allowed) return;
    expectConfirmGateError(gate.response.content[0].text);
  });

  it("refuses when confirm is false", () => {
    const gate = checkMutationAllowed(
      createTestConfig({ allowMutation: true }),
      { confirm: false },
      "test action",
    );
    expect(gate.allowed).toBe(false);
    if (gate.allowed) return;
    expectConfirmGateError(gate.response.content[0].text);
  });

  it("allows when mutation is enabled and confirm is true", () => {
    const gate = checkMutationAllowed(
      createTestConfig({ allowMutation: true }),
      { confirm: true },
      "test action",
    );
    expect(gate.allowed).toBe(true);
  });
});

describe("Confirmation gates on destructive tools", () => {
  describe.each(GATED_TOOLS)("%s", (toolName) => {
    it("is blocked with a clear confirm error when unconfirmed", async () => {
      const config =
        toolName.startsWith("pcap_")
          ? createTestConfig({ pcapDir: TEST_DATA_DIR, allowMutation: true })
          : createTestConfig({ allowMutation: true });

      const tools = registerGatedTool(toolName, config);
      const result = await tools.get(toolName)!(UNCONFIRMED_ARGS[toolName]);

      expect(result.isError).toBe(true);
      expectConfirmGateError(result.content[0].text);
    });

    it("is blocked with a clear confirm error when confirm is false", async () => {
      const config =
        toolName.startsWith("pcap_")
          ? createTestConfig({ pcapDir: TEST_DATA_DIR, allowMutation: true })
          : createTestConfig({ allowMutation: true });

      const tools = registerGatedTool(toolName, config);
      const result = await tools.get(toolName)!({
        ...UNCONFIRMED_ARGS[toolName],
        confirm: false,
      });

      expect(result.isError).toBe(true);
      expectConfirmGateError(result.content[0].text);
    });

    it("is blocked when mutation is disabled even with confirm:true", async () => {
      const config =
        toolName.startsWith("pcap_")
          ? createTestConfig({ pcapDir: TEST_DATA_DIR, allowMutation: false })
          : createTestConfig({ allowMutation: false });

      const tools = registerGatedTool(toolName, config);
      const result = await tools.get(toolName)!(confirmedArgs(toolName));

      expect(result.isError).toBe(true);
      expectMutationDisabledError(result.content[0].text);
    });
  });

  it("suricata_create_rule proceeds past the gate and writes local.rules when confirmed", async () => {
    const dir = await mkdtemp(join(tmpdir(), "suricata-create-gate-"));
    const localPath = join(dir, "local.rules");
    await writeFile(localPath, "");

    const rule =
      'alert tcp any any -> any any (msg:"gate-ok"; sid:1000101; rev:1;)';
    const tools = registerGatedTool(
      "suricata_create_rule",
      createTestConfig({ rulesDir: dir, allowMutation: true }),
    );

    const result = await tools.get("suricata_create_rule")!({
      rule,
      confirm: true,
    });

    expect(result.isError).not.toBe(true);
    const data = JSON.parse(result.content[0].text);
    expect(data.status).toBe("created");
    expect(data.sid).toBe(1000101);
    expect(await readFile(localPath, "utf-8")).toBe(rule + "\n");
  });

  it("suricata_create_rule does not write local.rules when the gate refuses", async () => {
    const dir = await mkdtemp(join(tmpdir(), "suricata-create-gate-refuse-"));
    const localPath = join(dir, "local.rules");
    const initial = "# placeholder\n";
    await writeFile(localPath, initial);

    const rule =
      'alert tcp any any -> any any (msg:"gate-blocked"; sid:1000102; rev:1;)';
    const tools = registerGatedTool(
      "suricata_create_rule",
      createTestConfig({ rulesDir: dir, allowMutation: true }),
    );

    const result = await tools.get("suricata_create_rule")!({ rule });

    expect(result.isError).toBe(true);
    expectConfirmGateError(result.content[0].text);
    expect(await readFile(localPath, "utf-8")).toBe(initial);
  });

  it("suricata_toggle_rule proceeds past the gate when confirmed", async () => {
    const dir = await mkdtemp(join(tmpdir(), "suricata-toggle-gate-"));
    const rule =
      'alert tcp any any -> any any (msg:"toggle-gate"; sid:1000103; rev:1;)';
    const localPath = join(dir, "local.rules");
    await writeFile(localPath, rule + "\n");

    const tools = registerGatedTool(
      "suricata_toggle_rule",
      createTestConfig({ rulesDir: dir, allowMutation: true }),
    );

    const result = await tools.get("suricata_toggle_rule")!({
      sid: 1000103,
      enable: false,
      confirm: true,
    });

    expect(result.isError).not.toBe(true);
    const data = JSON.parse(result.content[0].text);
    expect(data.status).toBe("updated");
    expect(data.enabled).toBe(false);
    expect(await readFile(localPath, "utf-8")).toBe("# " + rule + "\n");
  });

  it("suricata_reload_rules_docker proceeds past the gate when confirmed", async () => {
    const tools = registerGatedTool(
      "suricata_reload_rules_docker",
      createTestConfig({ allowMutation: true }),
    );

    const result = await tools.get("suricata_reload_rules_docker")!({
      confirm: true,
    });

    // Gate passed: failure is from docker/shell, not the confirmation gate.
    expect(result.content[0].text).not.toContain("destructive operation");
    expect(result.content[0].text).not.toContain("mutating tools are disabled");
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Error reloading rules");
  });

  it("pcap_replay_suricata proceeds past the gate when confirmed", async () => {
    const tools = registerGatedTool(
      "pcap_replay_suricata",
      createTestConfig({ pcapDir: TEST_DATA_DIR, allowMutation: true }),
    );

    const result = await tools.get("pcap_replay_suricata")!({
      filename: "definitely-missing-gate-test.pcap",
      confirm: true,
    });

    expect(result.content[0].text).not.toContain("destructive operation");
    expect(result.content[0].text).not.toContain("mutating tools are disabled");
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("PCAP file not found");
  });

  it("pcap_replay_zeek proceeds past the gate when confirmed", async () => {
    const tools = registerGatedTool(
      "pcap_replay_zeek",
      createTestConfig({ pcapDir: TEST_DATA_DIR, allowMutation: true }),
    );

    const result = await tools.get("pcap_replay_zeek")!({
      filename: "definitely-missing-gate-test.pcap",
      confirm: true,
    });

    expect(result.content[0].text).not.toContain("destructive operation");
    expect(result.content[0].text).not.toContain("mutating tools are disabled");
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("PCAP file not found");
  });

  it("pcap_replay_zeek is blocked when mutation is disabled", async () => {
    const tools = registerGatedTool(
      "pcap_replay_zeek",
      createTestConfig({ pcapDir: TEST_DATA_DIR, allowMutation: false }),
    );

    const result = await tools.get("pcap_replay_zeek")!({
      filename: "sample.pcap",
      confirm: true,
    });

    expect(result.isError).toBe(true);
    expectMutationDisabledError(result.content[0].text);
  });

  it("pcap_replay_suricata is blocked without confirm", async () => {
    const tools = registerGatedTool(
      "pcap_replay_suricata",
      createTestConfig({ pcapDir: TEST_DATA_DIR, allowMutation: true }),
    );

    const result = await tools.get("pcap_replay_suricata")!({
      filename: "sample.pcap",
    });

    expect(result.isError).toBe(true);
    expectConfirmGateError(result.content[0].text);
  });

  it("suricata_reload_rules_docker is blocked without confirm", async () => {
    const tools = registerGatedTool(
      "suricata_reload_rules_docker",
      createTestConfig({ allowMutation: true }),
    );

    const result = await tools.get("suricata_reload_rules_docker")!({});

    expect(result.isError).toBe(true);
    expectConfirmGateError(result.content[0].text);
  });
});
