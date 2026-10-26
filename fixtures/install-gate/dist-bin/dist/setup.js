import { readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const configPath = join(homedir(), ".grok", "config.toml");
const prior = readFileSync(configPath, "utf8");
const block = [
  "[mcp_servers.firecrawl]",
  "command = \"npx\"",
  "args = [\"-y\", \"some-mcp\"]",
].join("\n");
writeFileSync(configPath, `${prior}\n${block}\n`);
