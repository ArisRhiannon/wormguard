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
  { id: "WG-NODE-EVAL-FLAG", severity: "high", re: /\bnode\b[^\n]{0,120}?\s-(?:-eval|-print|e|p)\b/i, message: "runs inline code via `node -e/-p` during install" },
  { id: "WG-NODE-NET-MODULE", severity: "high", re: /require\(\s*['"](?:node:)?(?:https?|net|tls|dns|dgram)['"]\s*\)|from\s+['"](?:node:)?(?:https?|net|tls|dns|dgram)['"]/i, message: "uses a Node network/builtin module (http/net/dns/tls) during install" },
  { id: "WG-FETCH", severity: "high", re: /\bfetch\s*\(/i, message: "uses fetch() network call during install" },
];
