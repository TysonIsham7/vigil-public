#!/usr/bin/env python3
"""Write DistrustedCAs.swift from the shared intel blocklist. Do not hand-edit the output."""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
DATA = ROOT / "packages" / "intel" / "data" / "distrusted-cas.json"
VERSION = ROOT / "packages" / "intel" / "src" / "version.ts"
OUT = ROOT / "apps" / "safari" / "Shared (Extension)" / "Generated" / "DistrustedCAs.swift"


def swift_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def blocked_rows(data: dict) -> list[dict]:
    rows = []
    for item in data["intermediates"]:
        if item.get("action") != "block":
            continue
        rows.append(row(item["name"], item.get("sha256"), item["spkiSha256"]))
        for cross in item.get("crossSigns") or []:
            rows.append(row(item["name"], cross.get("sha256"), cross["spkiSha256"]))
    for root in data["roots"]:
        if root.get("action") != "block" or not root.get("spkiSha256"):
            continue
        rows.append(row(root["name"], root.get("sha256"), root["spkiSha256"]))
    return rows


def record_only(data: dict) -> list[str]:
    hashes = []
    for root in data["roots"]:
        if root.get("action") == "record-only" and root.get("spkiSha256"):
            hashes.append(root["spkiSha256"].lower())
    return hashes


def row(name: str, sha: str | None, spki: str) -> dict:
    return {
        "name": name,
        "sha256": sha.lower() if isinstance(sha, str) else None,
        "spkiSha256": spki.lower(),
    }


def fixture(data: dict) -> dict:
    for item in data["intermediates"]:
        pem = item.get("pem")
        if item.get("action") == "block" and pem:
            body = "".join(line for line in pem.splitlines() if "CERTIFICATE" not in line)
            der = base64.b64decode(body)
            return {
                "name": item["name"],
                "spkiSha256": item["spkiSha256"].lower(),
                "sha256": item["sha256"].lower(),
                "derBase64": base64.b64encode(der).decode("ascii"),
            }
    raise SystemExit("blocklist has no certificate to use as a parser fixture")


def intel_version() -> str:
    match = re.search(r'INTEL_VERSION = "([^"]+)"', VERSION.read_text(encoding="utf-8"))
    if not match:
        raise SystemExit("INTEL_VERSION was not found")
    return match.group(1)


def entry_line(item: dict) -> str:
    sha = "nil" if item["sha256"] is None else swift_string(item["sha256"])
    return (
        "    DistrustedCA(name: {name}, spkiSha256: {spki}, sha256: {sha}),".format(
            name=swift_string(item["name"]),
            spki=swift_string(item["spkiSha256"]),
            sha=sha,
        )
    )


def render(data: dict) -> str:
    rows = blocked_rows(data)
    ignored = record_only(data)
    sample = fixture(data)
    lines = [
        "// Generated from packages/intel/data/distrusted-cas.json. Do not edit.",
        "import Foundation",
        "",
        "struct DistrustedCA: Equatable {",
        "    let name: String",
        "    let spkiSha256: String",
        "    let sha256: String?",
        "}",
        "",
        "enum DistrustedBlocklist {",
        f"    static let intelVersion = {swift_string(intel_version())}",
        "    static let entries: [DistrustedCA] = [",
        *[entry_line(item) for item in rows],
        "    ]",
        "    static let recordOnlySpki: [String] = [",
        *[f"        {swift_string(item)}," for item in ignored],
        "    ]",
        "",
        "    static func match(spkiSha256: String?, sha256: String?) -> DistrustedCA? {",
        "        let spki = spkiSha256?.lowercased(with: Locale(identifier: \"en_US_POSIX\"))",
        "        let sha = sha256?.lowercased(with: Locale(identifier: \"en_US_POSIX\"))",
        "        return entries.first { entry in",
        "            (spki != nil && entry.spkiSha256 == spki) || (sha != nil && entry.sha256 == sha)",
        "        }",
        "    }",
        "}",
        "",
        "enum DistrustedFixture {",
        f"    static let name = {swift_string(sample['name'])}",
        f"    static let spkiSha256 = {swift_string(sample['spkiSha256'])}",
        f"    static let sha256 = {swift_string(sample['sha256'])}",
        f"    static let derBase64 = {swift_string(sample['derBase64'])}",
        "}",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    data = json.loads(DATA.read_text(encoding="utf-8"))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    payload = render(data)
    temporary = OUT.with_suffix(".swift.tmp")
    temporary.write_text(payload, encoding="utf-8")
    temporary.replace(OUT)


if __name__ == "__main__":
    main()
