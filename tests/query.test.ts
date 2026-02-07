import { describe, it, expect } from "vitest";
import {
  matchesCidr,
  matchesPartial,
  matchesWildcard,
  inTimeRange,
  matchesIp,
} from "../src/query/filters.js";
import {
  aggregate,
  topN,
  uniqueCount,
  numericStats,
} from "../src/query/aggregation.js";
import { bucketEvents } from "../src/query/timeline.js";

describe("Filter Functions", () => {
  describe("matchesCidr", () => {
    it("should match exact IP", () => {
      expect(matchesCidr("192.168.1.1", "192.168.1.1")).toBe(true);
    });

    it("should not match different IP", () => {
      expect(matchesCidr("192.168.1.1", "192.168.1.2")).toBe(false);
    });

    it("should match /24 CIDR", () => {
      expect(matchesCidr("192.168.1.100", "192.168.1.0/24")).toBe(true);
      expect(matchesCidr("192.168.2.1", "192.168.1.0/24")).toBe(false);
    });

    it("should match /16 CIDR", () => {
      expect(matchesCidr("192.168.50.1", "192.168.0.0/16")).toBe(true);
      expect(matchesCidr("192.169.0.1", "192.168.0.0/16")).toBe(false);
    });

    it("should match /8 CIDR", () => {
      expect(matchesCidr("10.5.6.7", "10.0.0.0/8")).toBe(true);
      expect(matchesCidr("11.0.0.1", "10.0.0.0/8")).toBe(false);
    });

    it("should match /32 CIDR (single host)", () => {
      expect(matchesCidr("192.168.1.1", "192.168.1.1/32")).toBe(true);
      expect(matchesCidr("192.168.1.2", "192.168.1.1/32")).toBe(false);
    });

    it("should handle invalid IPs gracefully", () => {
      expect(matchesCidr("not-an-ip", "192.168.1.0/24")).toBe(false);
      expect(matchesCidr("192.168.1.1", "not-a-cidr/24")).toBe(false);
    });
  });

  describe("matchesPartial", () => {
    it("should match substring (case-insensitive)", () => {
      expect(matchesPartial("ET MALWARE Win32/Emotet", "emotet")).toBe(true);
      expect(matchesPartial("ET MALWARE Win32/Emotet", "MALWARE")).toBe(true);
    });

    it("should not match non-existent substring", () => {
      expect(matchesPartial("ET MALWARE Win32/Emotet", "cobalt")).toBe(false);
    });

    it("should match exact string", () => {
      expect(matchesPartial("test", "test")).toBe(true);
    });
  });

  describe("matchesWildcard", () => {
    it("should match with asterisk wildcard", () => {
      expect(matchesWildcard("evil-domain.xyz", "*.xyz")).toBe(true);
      expect(matchesWildcard("evil-domain.com", "*.xyz")).toBe(false);
    });

    it("should match with question mark wildcard", () => {
      expect(matchesWildcard("test1.com", "test?.com")).toBe(true);
      expect(matchesWildcard("test12.com", "test?.com")).toBe(false);
    });

    it("should match exact string without wildcards", () => {
      expect(matchesWildcard("test.com", "test.com")).toBe(true);
    });
  });

  describe("inTimeRange", () => {
    it("should return true when no range specified", () => {
      expect(inTimeRange("2025-01-15T10:00:00")).toBe(true);
    });

    it("should filter by timeFrom", () => {
      expect(inTimeRange("2025-01-15T10:00:00", "2025-01-15T09:00:00")).toBe(true);
      expect(inTimeRange("2025-01-15T08:00:00", "2025-01-15T09:00:00")).toBe(false);
    });

    it("should filter by timeTo", () => {
      expect(inTimeRange("2025-01-15T10:00:00", undefined, "2025-01-15T11:00:00")).toBe(true);
      expect(inTimeRange("2025-01-15T12:00:00", undefined, "2025-01-15T11:00:00")).toBe(false);
    });

    it("should filter by both timeFrom and timeTo", () => {
      expect(inTimeRange("2025-01-15T10:00:00", "2025-01-15T09:00:00", "2025-01-15T11:00:00")).toBe(true);
      expect(inTimeRange("2025-01-15T08:00:00", "2025-01-15T09:00:00", "2025-01-15T11:00:00")).toBe(false);
      expect(inTimeRange("2025-01-15T12:00:00", "2025-01-15T09:00:00", "2025-01-15T11:00:00")).toBe(false);
    });
  });

  describe("matchesIp", () => {
    it("should return false for undefined IP", () => {
      expect(matchesIp(undefined, "192.168.1.0/24")).toBe(false);
    });

    it("should delegate to CIDR matching", () => {
      expect(matchesIp("192.168.1.100", "192.168.1.0/24")).toBe(true);
      expect(matchesIp("10.0.0.1", "192.168.1.0/24")).toBe(false);
    });
  });
});

describe("Aggregation Functions", () => {
  describe("aggregate", () => {
    it("should count occurrences", () => {
      const result = aggregate(["a", "b", "a", "c", "a", "b"]);
      expect(result[0].key).toBe("a");
      expect(result[0].count).toBe(3);
      expect(result[1].key).toBe("b");
      expect(result[1].count).toBe(2);
      expect(result[2].key).toBe("c");
      expect(result[2].count).toBe(1);
    });

    it("should calculate percentages", () => {
      const result = aggregate(["a", "a", "b", "b"]);
      expect(result[0].percentage).toBe(50);
    });

    it("should sort by count descending", () => {
      const result = aggregate(["z", "a", "a", "z", "z"]);
      expect(result[0].key).toBe("z");
      expect(result[1].key).toBe("a");
    });

    it("should handle empty array", () => {
      const result = aggregate([]);
      expect(result).toEqual([]);
    });
  });

  describe("topN", () => {
    it("should return top N items", () => {
      const items = aggregate(["a", "b", "c", "a", "b", "a"]);
      const top = topN(items, 2);
      expect(top.length).toBe(2);
      expect(top[0].key).toBe("a");
    });
  });

  describe("uniqueCount", () => {
    it("should count unique items", () => {
      expect(uniqueCount(["a", "b", "a", "c"])).toBe(3);
    });

    it("should return 0 for empty array", () => {
      expect(uniqueCount([])).toBe(0);
    });
  });

  describe("numericStats", () => {
    it("should calculate stats correctly", () => {
      const stats = numericStats([1, 2, 3, 4, 5]);
      expect(stats.min).toBe(1);
      expect(stats.max).toBe(5);
      expect(stats.avg).toBe(3);
      expect(stats.sum).toBe(15);
      expect(stats.count).toBe(5);
      expect(stats.median).toBe(3);
    });

    it("should handle even number of values for median", () => {
      const stats = numericStats([1, 2, 3, 4]);
      expect(stats.median).toBe(2.5);
    });

    it("should handle single value", () => {
      const stats = numericStats([42]);
      expect(stats.min).toBe(42);
      expect(stats.max).toBe(42);
      expect(stats.avg).toBe(42);
      expect(stats.median).toBe(42);
    });

    it("should handle empty array", () => {
      const stats = numericStats([]);
      expect(stats.count).toBe(0);
      expect(stats.sum).toBe(0);
    });
  });
});

describe("Timeline Functions", () => {
  describe("bucketEvents", () => {
    it("should bucket events into hourly intervals", () => {
      const events = [
        { timestamp: "2025-01-15T10:00:00.000Z" },
        { timestamp: "2025-01-15T10:15:00.000Z" },
        { timestamp: "2025-01-15T10:30:00.000Z" },
        { timestamp: "2025-01-15T11:00:00.000Z" },
        { timestamp: "2025-01-15T11:30:00.000Z" },
      ];

      const buckets = bucketEvents(events, "1h");
      expect(buckets.length).toBe(2);
      expect(buckets[0].count).toBe(3);
      expect(buckets[1].count).toBe(2);
    });

    it("should bucket events into 5-minute intervals", () => {
      const events = [
        { timestamp: "2025-01-15T10:00:00.000Z" },
        { timestamp: "2025-01-15T10:02:00.000Z" },
        { timestamp: "2025-01-15T10:06:00.000Z" },
        { timestamp: "2025-01-15T10:11:00.000Z" },
      ];

      const buckets = bucketEvents(events, "5m");
      expect(buckets.length).toBe(3);
      expect(buckets[0].count).toBe(2); // 10:00-10:05
      expect(buckets[1].count).toBe(1); // 10:05-10:10
      expect(buckets[2].count).toBe(1); // 10:10-10:15
    });

    it("should include breakdown when function provided", () => {
      const events = [
        { timestamp: "2025-01-15T10:00:00.000Z", severity: 1 },
        { timestamp: "2025-01-15T10:01:00.000Z", severity: 2 },
        { timestamp: "2025-01-15T10:02:00.000Z", severity: 1 },
      ];

      const buckets = bucketEvents(events, "1h", (e) => `sev_${e.severity}`);
      expect(buckets.length).toBe(1);
      expect(buckets[0].breakdown).toEqual({ sev_1: 2, sev_2: 1 });
    });

    it("should handle empty events", () => {
      const buckets = bucketEvents([], "1h");
      expect(buckets).toEqual([]);
    });

    it("should handle daily intervals", () => {
      const events = [
        { timestamp: "2025-01-15T10:00:00.000Z" },
        { timestamp: "2025-01-15T22:00:00.000Z" },
        { timestamp: "2025-01-16T05:00:00.000Z" },
      ];

      const buckets = bucketEvents(events, "1d");
      expect(buckets.length).toBe(2);
    });
  });
});
