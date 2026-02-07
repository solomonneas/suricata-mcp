import { describe, it, expect } from "vitest";
import { resolve } from "node:path";
import { parseEveFile } from "../src/parser/eve.js";
import { parseRule, parseRuleFile, loadAllRules } from "../src/parser/rules.js";

const TEST_EVE = resolve(import.meta.dirname, "../test-data/eve.json");
const TEST_RULES = resolve(import.meta.dirname, "../test-data/sample.rules");
const TEST_RULES_DIR = resolve(import.meta.dirname, "../test-data");

describe("EVE JSON Parser", () => {
  it("should parse all events from test EVE file", async () => {
    const events = await parseEveFile(TEST_EVE);
    expect(events.length).toBeGreaterThan(0);
  });

  it("should filter by event type", async () => {
    const alerts = await parseEveFile(TEST_EVE, { eventTypes: ["alert"] });
    expect(alerts.length).toBe(5);
    for (const event of alerts) {
      expect(event.event_type).toBe("alert");
    }
  });

  it("should filter flows", async () => {
    const flows = await parseEveFile(TEST_EVE, { eventTypes: ["flow"] });
    expect(flows.length).toBe(4);
    for (const event of flows) {
      expect(event.event_type).toBe("flow");
    }
  });

  it("should filter DNS events", async () => {
    const dns = await parseEveFile(TEST_EVE, { eventTypes: ["dns"] });
    expect(dns.length).toBe(4);
  });

  it("should filter HTTP events", async () => {
    const http = await parseEveFile(TEST_EVE, { eventTypes: ["http"] });
    expect(http.length).toBe(3);
  });

  it("should filter TLS events", async () => {
    const tls = await parseEveFile(TEST_EVE, { eventTypes: ["tls"] });
    expect(tls.length).toBe(3);
  });

  it("should filter fileinfo events", async () => {
    const files = await parseEveFile(TEST_EVE, { eventTypes: ["fileinfo"] });
    expect(files.length).toBe(2);
  });

  it("should filter SSH events", async () => {
    const ssh = await parseEveFile(TEST_EVE, { eventTypes: ["ssh"] });
    expect(ssh.length).toBe(2);
  });

  it("should filter anomaly events", async () => {
    const anomalies = await parseEveFile(TEST_EVE, { eventTypes: ["anomaly"] });
    expect(anomalies.length).toBe(2);
  });

  it("should filter stats events", async () => {
    const stats = await parseEveFile(TEST_EVE, { eventTypes: ["stats"] });
    expect(stats.length).toBe(1);
  });

  it("should respect maxEvents limit", async () => {
    const events = await parseEveFile(TEST_EVE, { maxEvents: 3 });
    expect(events.length).toBe(3);
  });

  it("should filter by time range", async () => {
    const events = await parseEveFile(TEST_EVE, {
      eventTypes: ["alert"],
      timeRange: {
        timeFrom: "2025-01-15T10:00:00",
        timeTo: "2025-01-15T10:02:00",
      },
    });
    // Should get alerts at 10:00, 10:01 but not 10:02 (exclusive comparison depends on format)
    expect(events.length).toBeGreaterThanOrEqual(2);
    expect(events.length).toBeLessThanOrEqual(3);
  });

  it("should return empty array for non-existent file", async () => {
    const events = await parseEveFile("/nonexistent/path/eve.json");
    expect(events).toEqual([]);
  });

  it("should parse alert event fields correctly", async () => {
    const alerts = await parseEveFile(TEST_EVE, { eventTypes: ["alert"], maxEvents: 1 });
    const alert = alerts[0] as any;
    expect(alert.event_type).toBe("alert");
    expect(alert.src_ip).toBeDefined();
    expect(alert.dest_ip).toBeDefined();
    expect(alert.alert).toBeDefined();
    expect(alert.alert.signature_id).toBeDefined();
    expect(alert.alert.signature).toBeDefined();
    expect(alert.alert.severity).toBeDefined();
    expect(alert.alert.action).toBeDefined();
  });

  it("should parse flow event fields correctly", async () => {
    const flows = await parseEveFile(TEST_EVE, { eventTypes: ["flow"], maxEvents: 1 });
    const flow = flows[0] as any;
    expect(flow.event_type).toBe("flow");
    expect(flow.flow).toBeDefined();
    expect(flow.flow.bytes_toserver).toBeDefined();
    expect(flow.flow.bytes_toclient).toBeDefined();
    expect(flow.flow.state).toBeDefined();
  });
});

describe("Suricata Rule Parser", () => {
  it("should parse a simple alert rule", () => {
    const rule = parseRule('alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Test Rule"; sid:1000001; rev:1; classtype:trojan-activity;)');
    expect(rule).not.toBeNull();
    expect(rule!.action).toBe("alert");
    expect(rule!.proto).toBe("tcp");
    expect(rule!.sid).toBe(1000001);
    expect(rule!.rev).toBe(1);
    expect(rule!.msg).toBe("Test Rule");
    expect(rule!.classtype).toBe("trojan-activity");
    expect(rule!.enabled).toBe(true);
  });

  it("should parse a disabled rule", () => {
    const rule = parseRule('# alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Disabled Rule"; sid:1000002; rev:1; classtype:misc-activity;)');
    expect(rule).not.toBeNull();
    expect(rule!.enabled).toBe(false);
    expect(rule!.sid).toBe(1000002);
  });

  it("should parse a drop rule", () => {
    const rule = parseRule('drop tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"Drop SSH"; sid:1000003; rev:1; classtype:attempted-admin;)');
    expect(rule).not.toBeNull();
    expect(rule!.action).toBe("drop");
  });

  it("should parse a pass rule", () => {
    const rule = parseRule('pass tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Pass HTTPS"; sid:1000004; rev:1; classtype:not-suspicious;)');
    expect(rule).not.toBeNull();
    expect(rule!.action).toBe("pass");
  });

  it("should return null for comments", () => {
    const rule = parseRule("# This is just a comment");
    expect(rule).toBeNull();
  });

  it("should return null for empty lines", () => {
    const rule = parseRule("");
    expect(rule).toBeNull();
  });

  it("should parse rule file", async () => {
    const rules = await parseRuleFile(TEST_RULES);
    expect(rules.length).toBeGreaterThan(0);
    const enabledRules = rules.filter((r) => r.enabled);
    const disabledRules = rules.filter((r) => !r.enabled);
    expect(enabledRules.length).toBeGreaterThan(0);
    expect(disabledRules.length).toBeGreaterThan(0);
  });

  it("should extract references", () => {
    const rule = parseRule('alert tcp any any -> any any (msg:"Test"; reference:url,abuse.ch/emotet; sid:999; rev:1;)');
    expect(rule).not.toBeNull();
    expect(rule!.reference).toContain("url,abuse.ch/emotet");
  });

  it("should extract content matches", () => {
    const rule = parseRule('alert tcp any any -> any any (msg:"Test"; content:"|16 03|"; content:"test"; sid:999; rev:1;)');
    expect(rule).not.toBeNull();
    expect(rule!.content).toContain("|16 03|");
    expect(rule!.content).toContain("test");
  });

  it("should load all rules from directory", async () => {
    const rules = await loadAllRules(TEST_RULES_DIR);
    expect(rules.length).toBeGreaterThan(0);
  });

  it("should return empty for non-existent rules directory", async () => {
    const rules = await loadAllRules("/nonexistent/dir");
    expect(rules).toEqual([]);
  });

  it("should parse bidirectional rules", () => {
    const rule = parseRule('alert tcp any any <> any any (msg:"Bidirectional"; sid:999; rev:1;)');
    expect(rule).not.toBeNull();
    expect(rule!.direction).toBe("<>");
  });
});
