export function matchesCidr(ip: string, cidr: string): boolean {
  if (!cidr.includes("/")) {
    return ip === cidr;
  }

  const [subnet, prefixStr] = cidr.split("/");
  const prefix = parseInt(prefixStr, 10);

  const ipNum = ipToNumber(ip);
  const subnetNum = ipToNumber(subnet);
  if (ipNum === null || subnetNum === null) return false;

  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  return (ipNum & mask) === (subnetNum & mask);
}

function ipToNumber(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;

  let result = 0;
  for (const part of parts) {
    const num = parseInt(part, 10);
    if (isNaN(num) || num < 0 || num > 255) return null;
    result = (result << 8) | num;
  }
  return result >>> 0;
}

export function matchesPartial(value: string, pattern: string): boolean {
  return value.toLowerCase().includes(pattern.toLowerCase());
}

export function matchesWildcard(value: string, pattern: string): boolean {
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/\?/g, ".");
  return new RegExp(`^${escaped}$`, "i").test(value);
}

export function inTimeRange(
  timestamp: string,
  timeFrom?: string,
  timeTo?: string,
): boolean {
  if (timeFrom && timestamp < timeFrom) return false;
  if (timeTo && timestamp > timeTo) return false;
  return true;
}

export function matchesIp(
  eventIp: string | undefined,
  filterIp: string,
): boolean {
  if (!eventIp) return false;
  return matchesCidr(eventIp, filterIp);
}
