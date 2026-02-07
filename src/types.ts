export type EventType =
  | "alert"
  | "flow"
  | "dns"
  | "http"
  | "tls"
  | "fileinfo"
  | "smtp"
  | "ssh"
  | "anomaly"
  | "stats"
  | "drop";

export interface EveBase {
  timestamp: string;
  event_type: EventType;
  src_ip?: string;
  src_port?: number;
  dest_ip?: string;
  dest_port?: number;
  proto?: string;
  flow_id?: number;
  in_iface?: string;
  community_id?: string;
}

export interface AlertEvent extends EveBase {
  event_type: "alert";
  alert: {
    action: "allowed" | "blocked";
    gid: number;
    signature_id: number;
    rev: number;
    signature: string;
    category: string;
    severity: number;
    metadata?: Record<string, string[]>;
  };
  app_proto?: string;
  payload?: string;
  payload_printable?: string;
  http?: HttpDetails;
  dns?: DnsDetails;
  tls?: TlsDetails;
}

export interface FlowEvent extends EveBase {
  event_type: "flow";
  app_proto?: string;
  flow: {
    pkts_toserver: number;
    pkts_toclient: number;
    bytes_toserver: number;
    bytes_toclient: number;
    start: string;
    end: string;
    age: number;
    state: string;
    reason: string;
    alerted: boolean;
  };
}

export interface DnsDetails {
  type?: string;
  id?: number;
  rrname?: string;
  rrtype?: string;
  rcode?: string;
  rdata?: string;
  answers?: Array<{
    rrname: string;
    rrtype: string;
    rdata: string;
    ttl: number;
  }>;
  grouped?: Record<string, string[]>;
  tx_id?: number;
}

export interface DnsEvent extends EveBase {
  event_type: "dns";
  dns: DnsDetails;
}

export interface HttpDetails {
  hostname?: string;
  url?: string;
  http_user_agent?: string;
  http_content_type?: string;
  http_method?: string;
  protocol?: string;
  status?: number;
  length?: number;
  http_refer?: string;
  redirect?: string;
}

export interface HttpEvent extends EveBase {
  event_type: "http";
  http: HttpDetails;
}

export interface TlsDetails {
  subject?: string;
  issuerdn?: string;
  serial?: string;
  fingerprint?: string;
  sni?: string;
  version?: string;
  notbefore?: string;
  notafter?: string;
  ja3?: { hash?: string; string?: string };
  ja3s?: { hash?: string; string?: string };
  ja4?: string;
}

export interface TlsEvent extends EveBase {
  event_type: "tls";
  tls: TlsDetails;
}

export interface FileinfoEvent extends EveBase {
  event_type: "fileinfo";
  fileinfo: {
    filename?: string;
    magic?: string;
    md5?: string;
    sha1?: string;
    sha256?: string;
    size?: number;
    state?: string;
    stored?: boolean;
    tx_id?: number;
    gaps?: boolean;
  };
  app_proto?: string;
  http?: HttpDetails;
}

export interface SmtpEvent extends EveBase {
  event_type: "smtp";
  smtp: {
    helo?: string;
    mail_from?: string;
    rcpt_to?: string[];
  };
  email?: {
    from?: string;
    to?: string[];
    subject?: string;
    attachment?: string[];
  };
}

export interface SshEvent extends EveBase {
  event_type: "ssh";
  ssh: {
    client?: {
      software_version?: string;
      proto_version?: string;
    };
    server?: {
      software_version?: string;
      proto_version?: string;
    };
  };
}

export interface AnomalyEvent extends EveBase {
  event_type: "anomaly";
  anomaly: {
    type?: string;
    event?: string;
    layer?: string;
    code?: number;
  };
  tx_id?: number;
}

export interface StatsEvent extends EveBase {
  event_type: "stats";
  stats: {
    uptime: number;
    capture?: {
      kernel_packets?: number;
      kernel_drops?: number;
      errors?: number;
    };
    decoder?: {
      pkts?: number;
      bytes?: number;
      ipv4?: number;
      ipv6?: number;
      tcp?: number;
      udp?: number;
      icmpv4?: number;
      icmpv6?: number;
    };
    detect?: {
      alert?: number;
      engines?: Array<{
        id: number;
        last_reload: string;
        rules_loaded: number;
        rules_failed: number;
      }>;
    };
    flow?: {
      tcp?: number;
      udp?: number;
      icmpv4?: number;
      icmpv6?: number;
    };
    app_layer?: {
      flow?: Record<string, number>;
      tx?: Record<string, number>;
    };
  };
}

export interface DropEvent extends EveBase {
  event_type: "drop";
  alert?: AlertEvent["alert"];
  drop: {
    reason?: string;
    action?: string;
  };
}

export type EveEvent =
  | AlertEvent
  | FlowEvent
  | DnsEvent
  | HttpEvent
  | TlsEvent
  | FileinfoEvent
  | SmtpEvent
  | SshEvent
  | AnomalyEvent
  | StatsEvent
  | DropEvent;

export interface SuricataRule {
  raw: string;
  enabled: boolean;
  action: string;
  proto: string;
  srcNet: string;
  srcPort: string;
  direction: string;
  dstNet: string;
  dstPort: string;
  sid: number;
  rev?: number;
  msg?: string;
  classtype?: string;
  reference?: string[];
  metadata?: string[];
  content?: string[];
}

export interface TimeRange {
  timeFrom?: string;
  timeTo?: string;
}

export type Interval = "1m" | "5m" | "15m" | "1h" | "1d";
