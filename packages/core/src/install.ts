import { redactEvidence } from "./redact.js";
import { createFinding } from "./taxonomy.js";
import type { Finding } from "./types.js";

export interface ModuleSpecifier {
  specifier: string;
  line: number;
  relative: boolean;
}

export interface ModuleGraph {
  specifiers: ModuleSpecifier[];
  dynamic: { line: number; evidence: string }[];
}

export interface LifecyclePlan {
  findings: Finding[];
  follow: string[];
}

const LIFECYCLE = ["preinstall", "install", "postinstall"] as const;

const CHILD_IMPORT = /(?:^|[^.\w])(?:node:)?child_process\b/;
const CHILD_CALL = /\b(?:execFileSync|execFile|execSync|spawnSync)\s*\(/;
const SHELL_C = /\b(?:sh|bash|zsh|dash)\s+-c\b|\b\/bin\/(?:sh|bash)\b/;
const AGENT_HOME = /~\/\.(?:grok|claude|agents|bashrc|zshrc|bash_profile|zprofile|zshenv|profile)\b|["'`]\.(?:grok|claude|agents|bashrc|zshrc|bash_profile|zprofile|zshenv|profile)\b|Library\/Application Support|(?:^|[/\\])\.(?:grok|claude|agents|bashrc|zshrc|bash_profile|zprofile|zshenv|profile)\b/;
const MCP = /\[mcp_servers[.\]]|["']mcpServers["']|mcp\.json|claude_desktop_config/;
const NPX = /\bnpx\b/;
const NPM_INSTALL = /\bnpm\s+(?:install|ci|update|exec|i)\b/;
const CURL_SH = /\b(?:curl|wget)\b[^|\n]{0,200}\|\s*(?:sudo\s+)?(?:\/bin\/)?(?:sh|bash|zsh)\b/;
const SCRIPT_FILE = /\b(?:node|bun|ts-node|tsx|sh|bash|zsh)\s+(?:--[\w.=-]+\s+)*['"]?((?:\.\/|\.\.\/)?[\w./@+-]+\.(?:js|mjs|cjs|ts|tsx|sh|bash))\b/g;

function finding(input: {
  id: string;
  severity: Finding["severity"];
  title: string;
  summary: string;
  why: string;
  remediation: string[];
  file: string;
  line: number;
  evidence: string;
  recommendationOnly: boolean;
}): Finding {
  return createFinding({
    id: input.id,
    severity: input.severity,
    confidence: "high",
    title: input.title,
    summary: input.summary,
    why: input.why,
    remediation: input.remediation,
    file: input.file,
    line: input.line,
    evidence: redactEvidence(input.evidence),
    agentAction: input.remediation[0] ?? "Do not install this package.",
    category: "install",
    recommendationOnly: input.recommendationOnly,
  });
}

/** Comment-stripped source with newlines kept. `://` is not treated as a line comment. */
function visibleCode(content: string): string {
  let out = "";
  let i = 0;
  let state: "code" | "line" | "block" | "sq" | "dq" | "tpl" = "code";
  while (i < content.length) {
    const char = content[i] ?? "";
    const next = content[i + 1];
    if (state === "line") {
      if (char === "\n") {
        state = "code";
        out += "\n";
      } else out += " ";
      i++;
      continue;
    }
    if (state === "block") {
      if (char === "*" && next === "/") {
        state = "code";
        out += "  ";
        i += 2;
        continue;
      }
      out += char === "\n" ? "\n" : " ";
      i++;
      continue;
    }
    if (state === "sq" || state === "dq" || state === "tpl") {
      out += char;
      if (char === "\\") {
        if (next !== undefined) out += next;
        i += next === undefined ? 1 : 2;
        continue;
      }
      const quote = state === "sq" ? "'" : state === "dq" ? "\"" : "`";
      if (char === quote) state = "code";
      i++;
      continue;
    }
    if (char === "/" && next === "/" && content[i - 1] !== ":") {
      state = "line";
      out += "  ";
      i += 2;
      continue;
    }
    if (char === "/" && next === "*") {
      state = "block";
      out += "  ";
      i += 2;
      continue;
    }
    if (char === "'") state = "sq";
    else if (char === "\"") state = "dq";
    else if (char === "`") state = "tpl";
    out += char;
    i++;
  }
  return out;
}

function firstLine(content: string, test: (line: string) => boolean): { line: number; evidence: string } | null {
  const rows = visibleCode(content).split("\n");
  for (let i = 0; i < rows.length; i++) {
    const line = rows[i] ?? "";
    if (line.trim() === "") continue;
    if (test(line)) return { line: i + 1, evidence: line };
  }
  return null;
}

function lineAt(content: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < content.length; i++) if (content[i] === "\n") line++;
  return line;
}

function snippetAt(content: string, index: number): string {
  const start = content.lastIndexOf("\n", index) + 1;
  const end = content.indexOf("\n", index);
  return content.slice(start, end === -1 ? content.length : end);
}

/** Join a relative specifier onto the importing file. Null when it leaves the package. */
export function resolveRelative(fromFile: string, spec: string): string | null {
  if (!spec.startsWith(".")) return null;
  const dir = fromFile.split("/").slice(0, -1).filter((part) => part && part !== ".");
  const parts = [...dir, ...spec.split("/")];
  const out: string[] = [];
  for (const part of parts) {
    if (!part || part === ".") continue;
    if (part === "..") {
      if (out.length === 0) return null;
      out.pop();
      continue;
    }
    out.push(part);
  }
  const joined = out.join("/");
  return joined || null;
}

function isIdentStart(char: string | undefined): boolean {
  return char !== undefined && /[A-Za-z_$]/.test(char);
}

function isIdentPart(char: string | undefined): boolean {
  return char !== undefined && /[A-Za-z0-9_$]/.test(char);
}

function skipSpace(source: string, index: number): { index: number; line: number } {
  let line = 0;
  let i = index;
  while (i < source.length) {
    const char = source[i];
    if (char === " " || char === "\t" || char === "\r") {
      i++;
      continue;
    }
    if (char === "\n") {
      line++;
      i++;
      continue;
    }
    break;
  }
  return { index: i, line };
}

function readString(source: string, index: number): { value: string; end: number; template: boolean } | null {
  const quote = source[index];
  if (quote !== "'" && quote !== "\"" && quote !== "`") return null;
  let value = "";
  let i = index + 1;
  while (i < source.length) {
    const char = source[i];
    if (char === "\\") {
      const next = source[i + 1];
      if (next === undefined) return null;
      value += next;
      i += 2;
      continue;
    }
    if (char === quote) return { value, end: i + 1, template: quote === "`" };
    value += char;
    i++;
  }
  return null;
}

/** One static specifier, or null when the argument is computed or unreadable. */
function singleSpecifier(args: string): string | null {
  const skipped = skipSpace(args, 0);
  const read = readString(args, skipped.index);
  if (!read) return null;
  if (read.template && read.value.includes("${")) return null;
  let i = read.end;
  while (i < args.length && (args[i] === " " || args[i] === "\t" || args[i] === "\n" || args[i] === "\r" || args[i] === ",")) i++;
  if (i !== args.length) return null;
  return read.value;
}

function readGroupedName(source: string, open: number): { name: string; end: number } | null {
  const spaced = skipSpace(source, open + 1);
  let i = spaced.index;
  if (!isIdentStart(source[i])) return null;
  const start = i;
  i++;
  while (isIdentPart(source[i])) i++;
  const name = source.slice(start, i);
  const after = skipSpace(source, i);
  if (source[after.index] !== ")") return null;
  return { name, end: after.index + 1 };
}

/** `const load = require` binds load. A call on the right, or a destructure, does not. */
function readRequireAlias(source: string, index: number, aliases: ReadonlySet<string>): { name: string; end: number } | null {
  let spaced = skipSpace(source, index);
  let i = spaced.index;
  if (!isIdentStart(source[i])) return null;
  const start = i;
  i++;
  while (isIdentPart(source[i])) i++;
  const name = source.slice(start, i);
  spaced = skipSpace(source, i);
  i = spaced.index;
  if (source[i] !== "=") return null;
  i++;
  spaced = skipSpace(source, i);
  i = spaced.index;
  if (source[i] === "(") {
    const grouped = readGroupedName(source, i);
    if (!grouped || (grouped.name !== "require" && !aliases.has(grouped.name))) return null;
    const after = skipSpace(source, grouped.end);
    if (source[after.index] === "(" || source.startsWith("?.", after.index)) return null;
    return { name, end: grouped.end };
  }
  if (!isIdentStart(source[i])) return null;
  const rhsStart = i;
  i++;
  while (isIdentPart(source[i])) i++;
  const rhs = source.slice(rhsStart, i);
  const after = skipSpace(source, i);
  if (source[after.index] === "(" || source.startsWith("?.", after.index) || source[after.index] === ".") return null;
  if (rhs !== "require" && !aliases.has(rhs)) return null;
  return { name, end: i };
}

function matchingCall(source: string, open: number): string | null {
  let depth = 0;
  let i = open;
  let quote: "'" | "\"" | "`" | null = null;
  while (i < source.length) {
    const char = source[i];
    if (quote) {
      if (char === "\\") {
        i += 2;
        continue;
      }
      if (char === quote) quote = null;
      i++;
      continue;
    }
    if (char === "'" || char === "\"" || char === "`") {
      quote = char;
      i++;
      continue;
    }
    if (char === "(") depth++;
    else if (char === ")") {
      depth--;
      if (depth === 0) return source.slice(open + 1, i);
    }
    i++;
  }
  return null;
}

function pushSpecifier(graph: ModuleGraph, specifier: string, line: number): void {
  graph.specifiers.push({ specifier, line, relative: specifier.startsWith(".") });
}

/**
 * Static relative imports and computed require/import calls.
 * Comments are ignored. A call whose argument is not one string literal is computed.
 * `(require)()`, `require?.()`, and a binding of require are computed even when the argument is a literal. Those literals are not followed.
 */
export function moduleGraph(content: string): ModuleGraph {
  const graph: ModuleGraph = { specifiers: [], dynamic: [] };
  const aliases = new Set<string>();
  let i = 0;
  let line = 1;
  let state: "code" | "line" | "block" = "code";
  while (i < content.length) {
    const char = content[i];
    const next = content[i + 1];
    if (state === "line") {
      if (char === "\n") {
        state = "code";
        line++;
      }
      i++;
      continue;
    }
    if (state === "block") {
      if (char === "\n") line++;
      if (char === "*" && next === "/") {
        state = "code";
        i += 2;
        continue;
      }
      i++;
      continue;
    }
    if (char === "\n") {
      line++;
      i++;
      continue;
    }
    if (char === "/" && next === "/") {
      state = "line";
      i += 2;
      continue;
    }
    if (char === "/" && next === "*") {
      state = "block";
      i += 2;
      continue;
    }
    if (char === "'" || char === "\"" || char === "`") {
      const read = readString(content, i);
      if (!read) {
        graph.dynamic.push({ line, evidence: snippetAt(content, i) });
        break;
      }
      if (read.template && read.value.includes("${") && /\b(?:require|import)\b/.test(read.value)) {
        graph.dynamic.push({ line, evidence: snippetAt(content, i) });
      }
      line += content.slice(i, read.end).split("\n").length - 1;
      i = read.end;
      continue;
    }
    if (!isIdentStart(char) || isIdentPart(content[i - 1])) {
      if (char === "(" && !isIdentPart(content[i - 1])) {
        const grouped = readGroupedName(content, i);
        if (grouped && (grouped.name === "require" || grouped.name === "import" || aliases.has(grouped.name))) {
          const after = skipSpace(content, grouped.end);
          if (content[after.index] === "(" || content.startsWith("?.", after.index)) {
            graph.dynamic.push({ line, evidence: snippetAt(content, i) });
          }
          line += content.slice(i, grouped.end).split("\n").length - 1;
          i = grouped.end;
          continue;
        }
      }
      i++;
      continue;
    }
    const start = i;
    const startLine = line;
    i++;
    while (isIdentPart(content[i])) i++;
    const word = content.slice(start, i);
    if (word === "const" || word === "let" || word === "var") {
      const alias = readRequireAlias(content, i, aliases);
      if (alias) {
        aliases.add(alias.name);
        line = startLine + content.slice(start, alias.end).split("\n").length - 1;
        i = alias.end;
      }
      continue;
    }
    if (aliases.has(word)) {
      const called = skipSpace(content, i);
      if (content[called.index] === "(" || content.startsWith("?.", called.index)) {
        graph.dynamic.push({ line: startLine, evidence: snippetAt(content, start) });
      }
      continue;
    }
    if (word !== "require" && word !== "import" && word !== "from") continue;
    const spaced = skipSpace(content, i);
    i = spaced.index;
    line = startLine + content.slice(start, i).split("\n").length - 1;
    if ((word === "require" || word === "import") && content.startsWith("?.", i)) {
      graph.dynamic.push({ line: startLine, evidence: snippetAt(content, start) });
      i += 2;
      continue;
    }
    if (word === "require" && content.startsWith(".resolve", i)) {
      i += ".resolve".length;
      const again = skipSpace(content, i);
      i = again.index;
      line += content.slice(spaced.index, i).split("\n").length - 1;
    }
    if ((word === "require" || word === "import") && content[i] === "(") {
      const args = matchingCall(content, i);
      const evidence = snippetAt(content, start);
      if (args === null) {
        graph.dynamic.push({ line: startLine, evidence });
        break;
      }
      const specifier = singleSpecifier(args);
      if (specifier === null) graph.dynamic.push({ line: startLine, evidence });
      else pushSpecifier(graph, specifier, startLine);
      const end = i + args.length + 2;
      line += content.slice(i, end).split("\n").length - 1;
      i = end;
      continue;
    }
    if ((word === "import" || word === "from") && (content[i] === "'" || content[i] === "\"" || content[i] === "`")) {
      const read = readString(content, i);
      if (!read || (read.template && read.value.includes("${"))) {
        graph.dynamic.push({ line: startLine, evidence: snippetAt(content, start) });
        break;
      }
      pushSpecifier(graph, read.value, startLine);
      line += content.slice(i, read.end).split("\n").length - 1;
      i = read.end;
    }
  }
  return graph;
}

function addOnce(findings: Finding[], seen: Set<string>, next: Finding | null): void {
  if (!next) return;
  const key = `${next.id}:${next.file}:${next.line}`;
  if (seen.has(key)) return;
  seen.add(key);
  findings.push(next);
}

/** Install behavior in one text file. Does not decide which files belong in the graph. */
export function installBehaviorFindings(filename: string, content: string): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();
  const child = firstLine(content, (line) => CHILD_IMPORT.test(line) || CHILD_CALL.test(line) || SHELL_C.test(line));
  if (child) {
    addOnce(findings, seen, finding({
      id: "INSTALL_CHILD_PROCESS",
      severity: "critical",
      title: "Bin graph runs a child process",
      summary: "The install graph imports child_process or calls execSync, execFile, spawn, or sh -c.",
      why: "A child process can run a shell command when this file loads. The gate does not run that command.",
      remediation: ["Do not install this package.", "Read the command the process would start before running the package."],
      file: filename,
      line: child.line,
      evidence: child.evidence,
      recommendationOnly: false,
    }));
  }
  const home = firstLine(content, (line) => AGENT_HOME.test(line));
  if (home) {
    addOnce(findings, seen, finding({
      id: "INSTALL_AGENT_HOME",
      severity: "critical",
      title: "Install path touches an agent home or shell startup file",
      summary: "The graph names ~/.grok, ~/.claude, ~/.agents, a shell rc file, or Application Support.",
      why: "Those locations hold agent configuration, skills, and shell startup. An installer can change what an agent runs next.",
      remediation: ["Do not install this package.", "Inspect that path before copying anything into an agent directory."],
      file: filename,
      line: home.line,
      evidence: home.evidence,
      recommendationOnly: false,
    }));
  }
  const mcp = firstLine(content, (line) => MCP.test(line));
  if (mcp) {
    addOnce(findings, seen, finding({
      id: "INSTALL_MCP_CONFIG",
      severity: "critical",
      title: "Install graph edits MCP configuration",
      summary: "The graph contains an MCP server block or an MCP config path.",
      why: "An MCP config change can start another program the next time an agent launches.",
      remediation: ["Do not install this package.", "Review the MCP block before it is written."],
      file: filename,
      line: mcp.line,
      evidence: mcp.evidence,
      recommendationOnly: false,
    }));
  }
  const fetch = firstLine(content, (line) => NPX.test(line) || NPM_INSTALL.test(line) || CURL_SH.test(line));
  if (fetch) {
    addOnce(findings, seen, finding({
      id: "INSTALL_RUNTIME_FETCH",
      severity: "critical",
      title: "Install graph downloads another package or script",
      summary: "The graph contains npx, npm install, or a curl or wget pipe into a shell.",
      why: "The extra download is not in this package, so this review cannot see what would run.",
      remediation: ["Do not install this package.", "Fetch that other artifact and review it on its own."],
      file: filename,
      line: fetch.line,
      evidence: fetch.evidence,
      recommendationOnly: false,
    }));
  }
  const instruction = agentInstruction(content);
  if (instruction) {
    addOnce(findings, seen, finding({
      id: "INSTALL_AGENT_INSTRUCTION",
      severity: "critical",
      title: "Text tells an agent to fetch a URL and follow it",
      summary: "A string pairs a URL with an instruction to fetch it and follow the result.",
      why: "An agent that reads the package can treat that string as an order and run something this review did not see.",
      remediation: ["Do not install this package.", "Do not follow instructions embedded in the package."],
      file: filename,
      line: instruction.line,
      evidence: instruction.evidence,
      recommendationOnly: false,
    }));
  }
  return findings;
}

function agentInstruction(content: string): { line: number; evidence: string } | null {
  const source = visibleCode(content);
  const url = /https?:\/\/[^\s'"`<>]+/gi;
  let match: RegExpExecArray | null;
  while ((match = url.exec(source))) {
    const start = Math.max(0, match.index - 240);
    const end = Math.min(source.length, match.index + match[0].length + 240);
    const slice = source.slice(start, end);
    const follow = /follow(?:\s+\w+){0,4}\s+instructions?/i.test(slice);
    const fetch = /\b(?:fetch|curl|wget|download)\b/i.test(slice);
    const agent = /\b(?:agent|assistant|llm|claude|grok|cursor)\b/i.test(slice);
    if (follow && (fetch || agent)) {
      return { line: lineAt(content, match.index), evidence: snippetAt(content, match.index) };
    }
  }
  return null;
}

export function scriptFiles(script: string): string[] {
  const found: string[] = [];
  const pattern = new RegExp(SCRIPT_FILE.source, "g");
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(script))) {
    const path = match[1];
    if (!path || path.includes("node_modules/") || /^https?:/i.test(path)) continue;
    if (!found.includes(path)) found.push(path);
  }
  return found;
}

function scriptLine(content: string, name: string): number {
  const lines = content.split("\n");
  const pattern = new RegExp(`"${name}"\\s*:`);
  for (let i = 0; i < lines.length; i++) if (pattern.test(lines[i] ?? "")) return i + 1;
  return 1;
}

/** Lifecycle scripts npm runs for a registry install, plus prepare as a separate note. */
export function lifecyclePlan(packageJson: string, scripts: Record<string, unknown> | undefined): LifecyclePlan {
  const findings: Finding[] = [];
  const follow: string[] = [];
  const block = scripts ?? {};
  for (const name of LIFECYCLE) {
    const script = block[name];
    if (typeof script !== "string" || script.trim() === "") continue;
    const line = scriptLine(packageJson, name);
    findings.push(finding({
      id: "INSTALL_LIFECYCLE_SCRIPT",
      severity: "critical",
      title: "Registry lifecycle script runs code",
      summary: `${name} is a shell or node command. npm runs it during install.`,
      why: "The script runs as the user who installs the package. The gate does not run it.",
      remediation: ["Do not install this package.", "Remove the lifecycle script and read the command before running it."],
      file: "package.json",
      line,
      evidence: script,
      recommendationOnly: false,
    }));
    findings.push(...installBehaviorFindings("package.json", script).map((item) => ({
      ...item,
      line,
      occurrenceId: `${item.id}:package.json:${line}`,
    })));
    for (const path of scriptFiles(script)) if (!follow.includes(path)) follow.push(path);
  }
  const prepare = block.prepare;
  if (typeof prepare === "string" && prepare.trim() !== "") {
    findings.push(finding({
      id: "INSTALL_PREPARE_SCRIPT",
      severity: "informational",
      title: "prepare script is present",
      summary: "package.json prepare is not run by a registry install. It is reported so it is not silent.",
      why: "npm runs prepare on a local install and on pack. Installing this exact version from the registry does not run it.",
      remediation: ["Read the prepare script before a local install."],
      file: "package.json",
      line: scriptLine(packageJson, "prepare"),
      evidence: prepare,
      recommendationOnly: true,
    }));
  }
  return { findings, follow };
}

export function dynamicFindings(filename: string, graph: ModuleGraph): Finding[] {
  return graph.dynamic.map((item) => finding({
    id: "INSTALL_DYNAMIC_CODE",
    severity: "critical",
    title: "Computed require or import",
    summary: "A require or import target is not a static string, so the file that would load is unknown.",
    why: "A computed module id can point at a different file on each machine. An allow would hide that file.",
    remediation: ["Do not install this package.", "Replace the computed import with a literal relative path and review that file."],
    file: filename,
    line: item.line,
    evidence: item.evidence,
    recommendationOnly: false,
  }));
}

export function unreadFinding(filename: string, reason: string): Finding {
  return finding({
    id: "INSTALL_UNREAD",
    severity: "critical",
    title: "Install graph file was not read",
    summary: "A file the bin, main, or lifecycle graph names could not be read.",
    why: "An allow would hide code that install or the bin can still run.",
    remediation: ["Do not install this package.", "Make the missing file readable text and scan again."],
    file: filename,
    line: 1,
    evidence: reason,
    recommendationOnly: false,
  });
}

export function budgetFinding(evidence: string): Finding {
  return finding({
    id: "INSTALL_FILE_BUDGET",
    severity: "critical",
    title: "Install gate file budget was hit",
    summary: "The gate stopped because the file count or byte budget was reached.",
    why: "Files past the budget were not reviewed. An allow would be a silent pass.",
    remediation: ["Do not install this package."],
    file: "(gate)",
    line: 1,
    evidence,
    recommendationOnly: false,
  });
}
