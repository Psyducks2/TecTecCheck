import { describe, it, expect } from "vitest";
import { groupBySeverity } from "./severity";
import type { Vulnerability } from "./types";

const vuln = (severity: Vulnerability["severity"], type: string): Vulnerability => ({
  id: type,
  module: "headers",
  type,
  severity,
  description: "d",
  evidence: null,
});

describe("groupBySeverity", () => {
  it("agrupa por severidade na ordem CRITICAL → LOW", () => {
    const result = groupBySeverity([
      vuln("LOW", "a"),
      vuln("CRITICAL", "b"),
      vuln("LOW", "c"),
      vuln("HIGH", "d"),
      vuln("MEDIUM", "e"),
    ]);
    expect(result.map((g) => g.severity)).toEqual([
      "CRITICAL",
      "HIGH",
      "MEDIUM",
      "LOW",
    ]);
    expect(result[0].items.map((v) => v.type)).toEqual(["b"]); // CRITICAL
    expect(result[1].items.map((v) => v.type)).toEqual(["d"]); // HIGH
    expect(result[2].items.map((v) => v.type)).toEqual(["e"]); // MEDIUM
    expect(result[3].items.map((v) => v.type)).toEqual(["a", "c"]); // LOW
  });

  it("retorna grupos vazios quando não há findings", () => {
    const result = groupBySeverity([]);
    expect(result).toHaveLength(4);
    expect(result.every((g) => g.items.length === 0)).toBe(true);
  });
});
