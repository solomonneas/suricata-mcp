import { writeFileSync } from "node:fs";

const SIGNATURES = [
  { sid: 2024001, msg: "ET MALWARE Win32/Emotet CnC Activity", category: "A Network Trojan was detected", severity: 1 },
  { sid: 2024002, msg: "ET SCAN Potential SSH Scan", category: "Attempted Information Leak", severity: 2 },
  { sid: 2024003, msg: "ET EXPLOIT OpenSSH Overflow Attempt", category: "Attempted Administrator Privilege Gain", severity: 1 },
  { sid: 2024004, msg: "ET DNS Query for Suspicious TLD", category: "Potentially Bad Traffic", severity: 3 },
  { sid: 2024010, msg: "ET MALWARE CobaltStrike Beacon Activity", category: "A Network Trojan was detected", severity: 1 },
  { sid: 2024011, msg: "ET POLICY Outbound SMTP Traffic", category: "Potential Corporate Privacy Violation", severity: 3 },
  { sid: 2024012, msg: "ET INFO Observed DNS Query to .top TLD", category: "Potentially Bad Traffic", severity: 3 },
  { sid: 2024013, msg: "SURICATA HTTP unable to match response to request", category: "Not Suspicious Traffic", severity: 3 },
];

const INTERNAL_IPS = ["192.168.1.10", "192.168.1.20", "192.168.1.50", "192.168.1.100", "192.168.1.150", "192.168.1.200", "10.0.1.5", "10.0.1.10"];
const EXTERNAL_IPS = ["93.184.216.34", "104.21.44.120", "185.220.101.1", "45.33.32.156", "8.8.8.8", "1.1.1.1", "203.0.113.50", "198.51.100.25"];
const DOMAINS = ["evil-domain.xyz", "c2-callback.biz", "google.com", "github.com", "cdn.example.com", "api.service.io", "phishing-site.top", "legit-corp.com"];
const USER_AGENTS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "curl/7.88.1", "Mozilla/5.0 (compatible; MSIE 10.0)", "python-requests/2.28.0", "Go-http-client/2.0"];
const JA3_HASHES = [
  { hash: "e7d705a3286e19ea42f587b344ee6865", label: "Metasploit" },
  { hash: "72a589da586844d7f0818ce684948eea", label: "CobaltStrike" },
  { hash: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", label: "Chrome" },
  { hash: "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9", label: "Firefox" },
];

function pick<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randomPort(): number {
  return 1024 + Math.floor(Math.random() * 64000);
}

function randomTimestamp(baseTime: Date, offsetMinutes: number): string {
  const ts = new Date(baseTime.getTime() + offsetMinutes * 60 * 1000);
  return ts.toISOString().replace("Z", "+0000").replace(/\.\d{3}/, `.${String(Math.floor(Math.random() * 1000000)).padStart(6, "0")}`);
}

function generateAlerts(baseTime: Date, count: number): string[] {
  const lines: string[] = [];
  for (let i = 0; i < count; i++) {
    const sig = pick(SIGNATURES);
    const action = Math.random() > 0.8 ? "blocked" : "allowed";
    lines.push(JSON.stringify({
      timestamp: randomTimestamp(baseTime, Math.random() * 1440),
      event_type: "alert",
      src_ip: pick(INTERNAL_IPS),
      src_port: randomPort(),
      dest_ip: pick(EXTERNAL_IPS),
      dest_port: pick([22, 53, 80, 443, 8080, 8443]),
      proto: pick(["TCP", "UDP"]),
      flow_id: Math.floor(Math.random() * 1000000),
      alert: { action, gid: 1, signature_id: sig.sid, rev: 1, signature: sig.msg, category: sig.category, severity: sig.severity },
    }));
  }
  return lines;
}

function generateFlows(baseTime: Date, count: number): string[] {
  const lines: string[] = [];
  for (let i = 0; i < count; i++) {
    const age = Math.floor(Math.random() * 3600);
    lines.push(JSON.stringify({
      timestamp: randomTimestamp(baseTime, Math.random() * 1440),
      event_type: "flow",
      src_ip: pick(INTERNAL_IPS),
      src_port: randomPort(),
      dest_ip: pick(EXTERNAL_IPS),
      dest_port: pick([22, 53, 80, 443, 8080]),
      proto: pick(["TCP", "UDP"]),
      flow_id: Math.floor(Math.random() * 1000000),
      app_proto: pick(["http", "tls", "dns", "ssh", "smtp", "failed"]),
      flow: {
        pkts_toserver: Math.floor(Math.random() * 500),
        pkts_toclient: Math.floor(Math.random() * 500),
        bytes_toserver: Math.floor(Math.random() * 100000),
        bytes_toclient: Math.floor(Math.random() * 500000),
        start: randomTimestamp(baseTime, Math.random() * 1440),
        end: randomTimestamp(baseTime, Math.random() * 1440 + age / 60),
        age,
        state: pick(["new", "established", "closed"]),
        reason: "timeout",
        alerted: Math.random() > 0.9,
      },
    }));
  }
  return lines;
}

function generateDns(baseTime: Date, count: number): string[] {
  const lines: string[] = [];
  for (let i = 0; i < count; i++) {
    const domain = pick(DOMAINS);
    lines.push(JSON.stringify({
      timestamp: randomTimestamp(baseTime, Math.random() * 1440),
      event_type: "dns",
      src_ip: pick(INTERNAL_IPS),
      src_port: randomPort(),
      dest_ip: pick(["8.8.8.8", "1.1.1.1"]),
      dest_port: 53,
      proto: "UDP",
      dns: {
        type: pick(["query", "answer"]),
        id: Math.floor(Math.random() * 65535),
        rrname: domain,
        rrtype: pick(["A", "AAAA", "CNAME", "MX", "TXT"]),
        rcode: pick(["NOERROR", "NXDOMAIN", "SERVFAIL"]),
        tx_id: 0,
      },
    }));
  }
  return lines;
}

function generateHttp(baseTime: Date, count: number): string[] {
  const lines: string[] = [];
  for (let i = 0; i < count; i++) {
    lines.push(JSON.stringify({
      timestamp: randomTimestamp(baseTime, Math.random() * 1440),
      event_type: "http",
      src_ip: pick(INTERNAL_IPS),
      src_port: randomPort(),
      dest_ip: pick(EXTERNAL_IPS),
      dest_port: pick([80, 8080, 8443]),
      proto: "TCP",
      http: {
        hostname: pick(DOMAINS),
        url: pick(["/", "/api/data", "/login", "/payload.exe", "/config.bin", "/index.html"]),
        http_user_agent: pick(USER_AGENTS),
        http_method: pick(["GET", "POST", "PUT"]),
        status: pick([200, 201, 301, 403, 404, 500]),
        length: Math.floor(Math.random() * 100000),
        http_content_type: pick(["text/html", "application/json", "application/octet-stream"]),
      },
    }));
  }
  return lines;
}

function generateTls(baseTime: Date, count: number): string[] {
  const lines: string[] = [];
  for (let i = 0; i < count; i++) {
    const sni = pick(DOMAINS);
    const ja3 = pick(JA3_HASHES);
    lines.push(JSON.stringify({
      timestamp: randomTimestamp(baseTime, Math.random() * 1440),
      event_type: "tls",
      src_ip: pick(INTERNAL_IPS),
      src_port: randomPort(),
      dest_ip: pick(EXTERNAL_IPS),
      dest_port: 443,
      proto: "TCP",
      tls: {
        sni,
        version: pick(["TLSv1.2", "TLSv1.3"]),
        subject: `CN=${sni}`,
        issuerdn: pick(["CN=Let's Encrypt Authority X3", "CN=GTS CA 1C3", "CN=FakeCA"]),
        ja3: { hash: ja3.hash },
        ja4: `t${pick(["12", "13"])}d${String(Math.floor(Math.random() * 999999)).padStart(6, "0")}_${ja3.hash.slice(0, 12)}`,
      },
    }));
  }
  return lines;
}

function generateBeaconingFlows(baseTime: Date): string[] {
  const lines: string[] = [];
  const srcIp = "192.168.1.100";
  const dstIp = "185.220.101.1";
  const dstPort = 443;
  // Generate 60 connections at ~5-minute intervals with slight jitter
  for (let i = 0; i < 60; i++) {
    const jitter = (Math.random() - 0.5) * 10;
    const offsetMin = i * 5 + jitter;
    lines.push(JSON.stringify({
      timestamp: randomTimestamp(baseTime, offsetMin),
      event_type: "flow",
      src_ip: srcIp,
      src_port: randomPort(),
      dest_ip: dstIp,
      dest_port: dstPort,
      proto: "TCP",
      flow_id: Math.floor(Math.random() * 1000000),
      app_proto: "tls",
      flow: {
        pkts_toserver: 5,
        pkts_toclient: 4,
        bytes_toserver: 512,
        bytes_toclient: 256,
        start: randomTimestamp(baseTime, offsetMin),
        end: randomTimestamp(baseTime, offsetMin + 0.5),
        age: 30,
        state: "closed",
        reason: "timeout",
        alerted: false,
      },
    }));
  }
  return lines;
}

function main() {
  const outputPath = process.argv[2] ?? "test-data/eve-generated.json";
  const alertCount = parseInt(process.argv[3] ?? "200", 10);
  const flowCount = parseInt(process.argv[4] ?? "500", 10);
  const baseTime = new Date("2025-01-15T00:00:00Z");

  const lines = [
    ...generateAlerts(baseTime, alertCount),
    ...generateFlows(baseTime, flowCount),
    ...generateDns(baseTime, 150),
    ...generateHttp(baseTime, 100),
    ...generateTls(baseTime, 100),
    ...generateBeaconingFlows(baseTime),
  ];

  // Add stats event
  lines.push(JSON.stringify({
    timestamp: randomTimestamp(baseTime, 1440),
    event_type: "stats",
    stats: {
      uptime: 86400,
      capture: { kernel_packets: 2000000, kernel_drops: 200, errors: 0 },
      decoder: { pkts: 1999800, bytes: 2147483648, ipv4: 1800000, ipv6: 199800, tcp: 1600000, udp: 380000, icmpv4: 15000, icmpv6: 4800 },
      detect: { alert: alertCount },
      flow: { tcp: 60000, udp: 20000, icmpv4: 600, icmpv6: 120 },
      app_layer: { flow: { http: 15000, tls: 30000, dns: 10000, ssh: 600, smtp: 250 }, tx: { http: 18000, dns: 11000 } },
    },
  }));

  // Shuffle to simulate real EVE output order
  lines.sort(() => Math.random() - 0.5);

  writeFileSync(outputPath, lines.join("\n") + "\n");
  console.log(`Generated ${lines.length} EVE JSON events to ${outputPath}`);
  console.log(`  Alerts: ${alertCount}`);
  console.log(`  Flows: ${flowCount + 60} (includes 60 beaconing flows)`);
  console.log(`  DNS: 150`);
  console.log(`  HTTP: 100`);
  console.log(`  TLS: 100`);
  console.log(`  Stats: 1`);
}

main();
