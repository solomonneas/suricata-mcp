# Suricata MCP Server

An MCP (Model Context Protocol) server that provides intelligent parsing, querying, and analysis of Suricata IDS/IPS EVE JSON logs. Enables LLMs to investigate alerts, analyze network flows, detect beaconing patterns, and manage rule sets through a structured tool interface.

## Features

- **20 tools** for comprehensive Suricata data analysis
- **3 resources** for quick reference data
- **3 prompts** for guided investigation workflows
- Alert querying, summaries, timelines, and top-N analysis
- Network flow analysis with bandwidth stats
- Protocol-specific tools: DNS, HTTP, TLS (with JA3/JA4), SSH, file extraction, anomalies
- C2 beaconing detection with jitter analysis and confidence scoring
- Suricata rule search and statistics
- Cross-type host and alert investigation
- Live engine commands via Unix socket
- Streaming parser for large EVE JSON files
- CIDR-aware IP filtering
- Gzip archive support

## Prerequisites

- Node.js 20+
- Suricata sensor producing EVE JSON logs

## Installation

```bash
git clone https://github.com/solomonneas/suricata-mcp.git
cd suricata-mcp
npm install
npm run build
```

## Configuration

Set environment variables to point at your Suricata installation:

| Variable | Default | Description |
|----------|---------|-------------|
| `SURICATA_EVE_LOG` | `/var/log/suricata/eve.json` | Path to primary EVE JSON log |
| `SURICATA_EVE_ARCHIVE` | `/var/log/suricata/` | Directory for rotated/archived logs |
| `SURICATA_RULES_DIR` | _(none)_ | Suricata rules directory (enables rule tools) |
| `SURICATA_MAX_RESULTS` | `1000` | Maximum results per query |
| `SURICATA_UNIX_SOCKET` | _(none)_ | Unix socket path for live commands |

## Usage

### Claude Desktop

Add to your Claude Desktop MCP configuration (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "suricata": {
      "command": "node",
      "args": ["/path/to/suricata-mcp/dist/index.js"],
      "env": {
        "SURICATA_EVE_LOG": "/var/log/suricata/eve.json",
        "SURICATA_RULES_DIR": "/etc/suricata/rules"
      }
    }
  }
}
```

### Standalone

```bash
SURICATA_EVE_LOG=/var/log/suricata/eve.json node dist/index.js
```

### Development

```bash
npm run dev          # Watch mode with tsx
npm run build        # Production build
npm test             # Run test suite
npm run lint         # Type-check
```

## Tools

### Alert Analysis

| Tool | Description |
|------|-------------|
| `suricata_query_alerts` | Search alerts by SID, signature, category, severity, IP, port, protocol, action, time range |
| `suricata_alert_summary` | Aggregated alert statistics grouped by signature, category, severity, source, or destination |
| `suricata_top_alerts` | Top alerts by frequency and severity with unique source/destination counts |
| `suricata_alert_timeline` | Time-bucketed alert counts with severity breakdown (1m/5m/15m/1h/1d intervals) |

### Flow Analysis

| Tool | Description |
|------|-------------|
| `suricata_query_flows` | Search flows by IP, port, protocol, app protocol, min bytes, min duration, state |
| `suricata_flow_summary` | Top talkers, protocol distribution, bandwidth stats, unique IP pairs |
| `suricata_beaconing_detection` | Detect C2 beaconing via connection interval analysis with jitter and confidence scoring |

### Protocol Analysis

| Tool | Description |
|------|-------------|
| `suricata_query_dns` | Search DNS queries by name, source IP, record type, response code |
| `suricata_query_http` | Search HTTP transactions by hostname, URL, method, status, user-agent |
| `suricata_query_tls` | Search TLS connections by SNI, JA3/JA4 fingerprint, certificate subject/issuer |
| `suricata_query_ssh` | Search SSH connections by client/server software version |
| `suricata_query_fileinfo` | Search extracted files by name, magic type, hash (MD5/SHA256), size |
| `suricata_query_anomalies` | Search protocol anomalies by type, source/destination IP |

### Rule Management

| Tool | Description |
|------|-------------|
| `suricata_search_rules` | Search rule files by SID, message, classtype, reference, content |
| `suricata_rule_stats` | Rule set statistics: total, enabled/disabled, by action, by classtype |

### Engine & Live Commands

| Tool | Description |
|------|-------------|
| `suricata_engine_stats` | Suricata capture, decoder, detect, and flow statistics |
| `suricata_reload_rules` | Trigger live rule reload via Unix socket |
| `suricata_iface_stat` | Interface capture statistics via Unix socket |

### Cross-Type Investigation

| Tool | Description |
|------|-------------|
| `suricata_investigate_host` | Full investigation of a host across all event types (alerts, flows, DNS, HTTP, TLS, files, SSH, anomalies) |
| `suricata_investigate_alert` | Deep alert investigation with correlated flow and protocol data |

## Resources

| URI | Description |
|-----|-------------|
| `suricata://event-types` | All EVE event types with field descriptions |
| `suricata://stats/current` | Latest engine performance statistics |
| `suricata://rules/summary` | Rule set summary (if configured) |

## Prompts

| Prompt | Description |
|--------|-------------|
| `investigate-alert` | Guided alert investigation workflow |
| `hunt-for-threats` | Proactive threat hunting methodology |
| `daily-alert-report` | Daily alert summary report template |

## Architecture

```
suricata-mcp/
  src/
    index.ts              # MCP server entry, tool registration
    config.ts             # Environment config
    types.ts              # EVE JSON type definitions
    parser/
      eve.ts              # Streaming EVE JSON parser (supports .gz)
      rules.ts            # Suricata rule file parser
    query/
      engine.ts           # Query engine coordinating file reads
      filters.ts          # CIDR, wildcard, time range, IP matching
      aggregation.ts      # Statistical aggregation, top-N, numeric stats
      timeline.ts         # Time-bucketed event aggregation
    tools/
      alerts.ts           # Alert analysis tools
      flows.ts            # Flow analysis tools
      dns.ts              # DNS query tools
      http.ts             # HTTP transaction tools
      tls.ts              # TLS/JA3/JA4 tools
      files.ts            # File extraction tools
      ssh.ts              # SSH protocol tools
      anomalies.ts        # Anomaly detection tools
      rules.ts            # Rule management tools
      stats.ts            # Engine stats tools
      investigation.ts    # Cross-type investigation
    analytics/
      beaconing.ts        # C2 beacon detection
      ja3.ts              # Known JA3 fingerprint database
    socket/
      client.ts           # Unix socket for live commands
    resources.ts          # MCP resources
    prompts.ts            # MCP prompts
  tests/
    parser.test.ts        # Parser unit tests
    query.test.ts         # Filter and aggregation tests
    tools.test.ts         # Tool handler integration tests
  test-data/
    eve.json              # Sample EVE JSON data
    sample.rules          # Sample Suricata rules
  scripts/
    generate-eve.ts       # Mock EVE data generator
```

## Mock Data Generator

Generate realistic EVE JSON test data:

```bash
npm run generate-eve                                    # Default: 200 alerts, 500 flows
npx tsx scripts/generate-eve.ts output.json 500 1000    # Custom: 500 alerts, 1000 flows
```

Generated data includes realistic alert signatures (ET rules), protocol diversity (HTTP, TLS, DNS, SSH), C2 beaconing patterns, and known-suspicious JA3 fingerprints.

## Testing

```bash
npm test             # Run all tests
npm run test:watch   # Watch mode
```

The test suite covers:
- EVE JSON parser with sample events (event type filtering, time ranges, max limits)
- Suricata rule file parser (alert/drop/pass rules, disabled rules, references, content)
- Query filter functions (CIDR matching, partial matching, wildcards, time ranges)
- Aggregation and timeline functions
- All tool handlers with realistic test data

## Supported EVE Event Types

| Type | Description |
|------|-------------|
| `alert` | IDS/IPS alerts with signature, severity, action |
| `flow` | Network flow records with byte/packet counts |
| `dns` | DNS queries and responses |
| `http` | HTTP transactions |
| `tls` | TLS handshakes with JA3/JA4 fingerprints |
| `fileinfo` | File extraction metadata with hashes |
| `smtp` | SMTP transactions |
| `ssh` | SSH protocol information |
| `anomaly` | Protocol anomalies |
| `stats` | Engine performance statistics |
| `drop` | Dropped packets (IPS mode) |

## License

MIT
