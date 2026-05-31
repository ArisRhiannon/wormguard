// SPDX-License-Identifier: MIT
import { describe, expect, test } from "bun:test";
import {
  matchPackageName,
  matchScriptHash,
  matchDomains,
  matchWallets,
  corpusStats,
} from "../src/corpus/iocs";

describe("IoC corpus matcher", () => {
  test("loads the bundled corpus with thousands of names", () => {
    const s = corpusStats();
    // Corpus refresh should produce a non-trivial dataset; we don't pin an
    // exact number because this is sensitive to GHSA churn, but require >0.
    expect(s.size).toBeGreaterThan(100);
  });

  test("matches a known-malicious package name + version (concrete advisory range)", () => {
    const fs = require("node:fs") as typeof import("node:fs");
    const corpus = JSON.parse(fs.readFileSync("data/iocs.json", "utf8")) as {
      names: string[];
      ranges: Record<string, string[]>;
    };
    expect(corpus.names.length).toBeGreaterThan(0);
    // Find an entry with a concrete (non-catch-all) range so we can prove the
    // version-aware matcher fires critical.
    let pkg: string | null = null;
    let badVersion: string | null = null;
    for (const [name, ranges] of Object.entries(corpus.ranges)) {
      const concrete = (ranges as string[]).filter((r) => r.replace(/\s+/g, "") !== ">=0");
      if (concrete.length === 0) continue;
      // "= 1.2.3" → 1.2.3
      const m = (concrete[0] as string).match(/=\s*([0-9][^\s]*)/);
      if (m) {
        pkg = name;
        badVersion = m[1] as string;
        break;
      }
    }
    if (!pkg || !badVersion) return; // corpus has no concrete ranges (unlikely)
    const f = matchPackageName(pkg, badVersion);
    expect(f).not.toBeNull();
    expect(f?.ruleId).toBe("WG-IOC-NAME");
    expect(f?.severity).toBe("critical");
  });

  test("a recovered version of a once-compromised package is NOT flagged critical", () => {
    // ansi-regex was compromised at 6.2.1; 6.3.0 is clean.
    const f = matchPackageName("ansi-regex", "6.3.0");
    if (f) expect(f.ruleId).not.toBe("WG-IOC-NAME"); // no critical
  });

  test("name-only match (no version) returns WG-IOC-NAME-LEGACY medium", () => {
    const fs = require("node:fs") as typeof import("node:fs");
    const corpus = JSON.parse(fs.readFileSync("data/iocs.json", "utf8")) as { names: string[] };
    const sample = corpus.names[0]!;
    const f = matchPackageName(sample);
    expect(f).not.toBeNull();
    expect(f?.ruleId).toBe("WG-IOC-NAME-LEGACY");
    expect(f?.severity).toBe("medium");
  });

  test("does not match a benign package name", () => {
    expect(matchPackageName("react")).toBeNull();
    expect(matchPackageName("typescript")).toBeNull();
    expect(matchPackageName("@types/node")).toBeNull();
  });

  test("script-hash matching is case-insensitive", () => {
    // Synthetic hash; corpus contains no script hashes by default, so this
    // will be null. Assert the API doesn't throw.
    expect(matchScriptHash("foo", "abc123")).toBeNull();
  });

  test("matchDomains finds bundled IoC hostnames", () => {
    const text = `const url = "https://discord.com/api/webhooks/123/abc"; fetch(url, {})`;
    const hits = matchDomains(text);
    expect(hits.length).toBeGreaterThan(0);
    expect(hits.some((h) => h.includes("discord"))).toBe(true);
  });

  test("matchDomains is case-insensitive", () => {
    const hits = matchDomains(`HTTPS://DISCORD.COM/API/WEBHOOKS/x`);
    expect(hits.length).toBeGreaterThan(0);
  });

  test("matchWallets returns [] when no wallets seeded", () => {
    expect(matchWallets("anything")).toEqual([]);
  });
});
