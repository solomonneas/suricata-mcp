// Known suspicious JA3 fingerprints commonly associated with malware families
// and penetration testing tools. These are well-documented in threat intelligence.
export const KNOWN_JA3_HASHES: Record<string, string> = {
  "e7d705a3286e19ea42f587b344ee6865": "Metasploit/Meterpreter",
  "72a589da586844d7f0818ce684948eea": "CobaltStrike",
  "a0e9f5d64349fb13191bc781f81f42e1": "CobaltStrike (4.x)",
  "b62e3f304e4b8f8e3f3b4e2e5c5b5e2a": "Trickbot",
  "51c64c77e60f3980eea90869b68c58a8": "Emotet",
  "6734f37431670b3ab4292b8f60f29984": "Tofsee",
  "4d7a28d6f2263ed61de88ca66eb2e557": "Dridex",
  "c12f54a256546d8c3fc5ab45189f5d17": "PoshC2",
  "3b5074b1b5d032e5620f69f9f700ff0e": "Empire/PowerShell",
  "19e29534fd49dd27d09234e639c4057e": "Sliver C2",
};

export function lookupJa3(hash: string): string | null {
  return KNOWN_JA3_HASHES[hash] ?? null;
}

export function isKnownMaliciousJa3(hash: string): boolean {
  return hash in KNOWN_JA3_HASHES;
}

export function getAllKnownJa3(): Array<{ hash: string; label: string }> {
  return Object.entries(KNOWN_JA3_HASHES).map(([hash, label]) => ({
    hash,
    label,
  }));
}
