export interface SuricataConfig {
  evePath: string;
  eveArchiveDir: string;
  rulesDir: string | null;
  maxResults: number;
  unixSocket: string | null;
}

export function getConfig(): SuricataConfig {
  return {
    evePath: process.env.SURICATA_EVE_LOG ?? "/var/log/suricata/eve.json",
    eveArchiveDir:
      process.env.SURICATA_EVE_ARCHIVE ?? "/var/log/suricata/",
    rulesDir: process.env.SURICATA_RULES_DIR ?? null,
    maxResults: parseInt(process.env.SURICATA_MAX_RESULTS ?? "1000", 10),
    unixSocket: process.env.SURICATA_UNIX_SOCKET ?? null,
  };
}
