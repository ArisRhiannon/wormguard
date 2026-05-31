import type { Severity } from "./types";

export interface Rule {
  id: string;
  severity: Severity;
  re: RegExp;
  message: string;
}

/** Heuristic danger signals in lifecycle-script command strings. Order is not significant. */
export const SCRIPT_RULES: Rule[] = [
  { id: "WG-SHELL-PIPE", severity: "critical", re: /\|\s*(sh|bash|zsh|powershell|pwsh)\b/i, message: "pipes content into a shell (download-and-run)" },
  { id: "WG-NET-DOWNLOAD", severity: "high", re: /\b(curl|wget|invoke-webrequest|nc|ncat|telnet)\b/i, message: "uses a network download/transfer tool during install" },
  { id: "WG-CHILD-PROCESS", severity: "high", re: /child_process|execSync|spawnSync|\bspawn\s*\(|\bexec\s*\(/i, message: "spawns child processes during install" },
  { id: "WG-EVAL", severity: "high", re: /\beval\s*\(|new\s+Function\s*\(/i, message: "uses eval / dynamic code execution" },
  { id: "WG-SECRET-PATH", severity: "high", re: /\.npmrc|\.aws|\.ssh|\.netrc|\.git\/config|id_rsa|(^|[^a-zA-Z])\.env([^a-zA-Z]|$)/i, message: "references credential / secret file paths" },
  { id: "WG-ENV-ENUM", severity: "medium", re: /process\.env(\b|\[|\.)/i, message: "reads environment variables during install" },
  { id: "WG-BASE64", severity: "medium", re: /base64|\batob\s*\(|from\s*\(\s*['"][^'"]*['"]\s*,\s*['"]base64/i, message: "base64 decode (possible obfuscated payload)" },
  { id: "WG-SELF-PROPAGATE", severity: "medium", re: /node_modules\//i, message: "writes into node_modules paths (possible self-propagation)" },
];
