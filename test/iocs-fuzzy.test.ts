// SPDX-License-Identifier: MIT
import { describe, expect, test } from "bun:test";
import { iocFuzzyFindings, resetIocFuzzyCache } from "../src/corpus/iocs-fuzzy";
import { readFileSync, existsSync } from "node:fs";

describe("IoC fuzzy matching (against confirmed-malicious names)", () => {
  test("returns [] for benign names that are nowhere near the corpus", () => {
    resetIocFuzzyCache();
    expect(iocFuzzyFindings(["react", "typescript", "@types/node"])).toEqual([]);
  });

  test("does NOT re-emit when project name is itself in the corpus (exact match)", () => {
    if (!existsSync("data/iocs.json")) return;
    resetIocFuzzyCache();
    const corpus = JSON.parse(readFileSync("data/iocs.json", "utf8")) as { names: string[] };
    const sample = corpus.names[0];
    if (typeof sample !== "string") return;
    expect(iocFuzzyFindings([sample])).toEqual([]); // covered by WG-IOC-NAME
  });

  test("emits WG-IOC-NEAR (high) for a name 1 edit from a malicious entry", () => {
    if (!existsSync("data/iocs.json")) return;
    resetIocFuzzyCache();
    const corpus = JSON.parse(readFileSync("data/iocs.json", "utf8")) as { names: string[] };
    // Pick a corpus name and mutate one character.
    const sample = corpus.names.find((n) => n.length > 4 && /^[a-z0-9-_]+$/.test(n)) ?? corpus.names[0];
    if (typeof sample !== "string") return;
    const mutated = sample.slice(0, -1) + (sample.slice(-1) === "x" ? "y" : "x");
    const f = iocFuzzyFindings([mutated]);
    expect(f.length).toBe(1);
    expect(f[0]?.ruleId).toBe("WG-IOC-NEAR");
    expect(f[0]?.severity).toBe("high");
    expect(f[0]?.message).toContain(sample);
  });

  test("does NOT emit for a name that's distance >=2 from every malicious entry", () => {
    resetIocFuzzyCache();
    // A name that is unlikely to be 1-edit-away from any entry.
    expect(iocFuzzyFindings(["this-name-is-very-very-unlikely-to-be-malicious-or-typosquat-12345"])).toEqual([]);
  });
});
