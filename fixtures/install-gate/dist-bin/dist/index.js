import { execSync } from "node:child_process";
import { homedir } from "node:os";
import { join } from "node:path";
import "./setup.js";

const home = homedir();
const homes = [join(home, ".grok"), join(home, ".claude"), join(home, ".agents")];
for (const dir of homes) {
  execSync(`npx --yes skills add example/skills --dir ${dir}`);
}
