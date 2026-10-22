export interface VisibleLine {
  lineNo: number;
  code: string;
  raw: string;
}

/**
 * Line-oriented view of source. Blank lines and // or block-comment lines are
 * skipped. A trailing comment is removed before matching. HTML comments on a
 * single line are removed the same way.
 */
export function visibleLines(content: string): VisibleLine[] {
  const rows = content.split("\n");
  const out: VisibleLine[] = [];
  let inBlock = false;
  for (let i = 0; i < rows.length; i++) {
    const raw = (rows[i] ?? "").replace(/\r$/, "");
    let idx = 0;
    let code = "";
    if (inBlock) {
      const end = raw.indexOf("*/");
      if (end === -1) continue;
      inBlock = false;
      idx = end + 2;
    }
    while (idx < raw.length) {
      if (raw.startsWith("<!--", idx)) {
        const end = raw.indexOf("-->", idx + 4);
        if (end === -1) {
          break;
        }
        idx = end + 3;
        continue;
      }
      if (raw.startsWith("//", idx)) break;
      if (raw.startsWith("/*", idx)) {
        const end = raw.indexOf("*/", idx + 2);
        if (end === -1) {
          inBlock = true;
          break;
        }
        idx = end + 2;
        continue;
      }
      code += raw[idx];
      idx++;
    }
    if (code.trim() === "") continue;
    out.push({ lineNo: i + 1, code, raw });
  }
  return out;
}
