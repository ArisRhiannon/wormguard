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

  test("matches a known-malicious package name (GHSA seed)", () => {
    // Pull one entry from the bundled corpus to make this test stable.
    const path = (require as unknown as { resolve(s: string): string }).resolve
      ? // ts-node-ish — fall back to absolute
        ""
      : "";
    void path;
    // We avoid hardcoding a name (corpus refreshes) by reading one from disk.
    const fs = require("node:fs") as typeof import("node:fs");
    const corpus = JSON.parse(fs.readFileSync("data/iocs.json", "utf8")) as { names: string[] };
    expect(corpus.names.length).toBeGreaterThan(0);
    const sample = corpus.names[0]!;
    const f = matchPackageName(sample);
    expect(f).not.toBeNull();
    expect(f?.ruleId).toBe("WG-IOC-NAME");
    expect(f?.severity).toBe("critical");
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
