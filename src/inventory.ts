import { readdirSync, readFileSync, existsSync } from "node:fs";
import { join, basename } from "node:path";
import type { LifecycleScripts } from "./types";

export interface InstalledPackage {
  name: string;
  dir: string;
  scripts: LifecycleScripts;
}

const LIFECYCLE = ["preinstall", "install", "postinstall", "prepare"] as const;

function collect(dir: string, out: InstalledPackage[]): void {
  const pj = join(dir, "package.json");
  if (!existsSync(pj)) return;
  let json: { name?: unknown; scripts?: Record<string, unknown> };
  try {
    json = JSON.parse(readFileSync(pj, "utf8"));
  } catch {
    return;
  }
  const s = json.scripts ?? {};
  const scripts: LifecycleScripts = {};
  for (const k of LIFECYCLE) {
    const v = s[k];
    if (typeof v === "string") scripts[k] = v;
  }
  out.push({ name: typeof json.name === "string" ? json.name : basename(dir), dir, scripts });
}

/** Scan `<root>/node_modules` for installed packages and their lifecycle scripts. */
export function scanNodeModules(root: string): InstalledPackage[] {
  const nm = join(root, "node_modules");
  if (!existsSync(nm)) return [];
  const out: InstalledPackage[] = [];
  for (const entry of readdirSync(nm)) {
    if (entry.startsWith(".")) continue;
    const full = join(nm, entry);
    if (entry.startsWith("@")) {
      for (const sub of readdirSync(full)) collect(join(full, sub), out);
    } else {
      collect(full, out);
    }
  }
  return out;
}
