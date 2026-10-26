import { describe, expect, it } from "vitest";
import { redactEvidence } from "../src/redact.js";

describe("redactEvidence", () => {
  it("removes DSNs, URL userinfo, and ADO connection strings", () => {
    const secret = "vigilTestDbSecret";
    const line = [
      `mysql://app:${secret}@db.internal/app`,
      `mongodb+srv://app:${secret}@cluster.example/db`,
      `postgres://app:${secret}@db.internal:5432/app`,
      `redis://:${secret}@cache.internal:6379/0`,
      `https://app:${secret}@example.com/path`,
      `Server=tcp:db.internal,1433;User ID=sa;Password=${secret};`,
      `Password=${secret}`,
    ].join(" ");
    const redacted = redactEvidence(line);
    expect(redacted).not.toContain(secret);
    expect(redacted).not.toContain("User ID=sa");
    expect(redacted).not.toContain("mysql://");
    expect(redacted).not.toContain("mongodb+srv://");
    expect(redacted).not.toContain("postgres://");
    expect(redacted).not.toContain("redis://");
    expect(redacted).toContain("[redacted connection string]");
    expect(redactEvidence(`Password=${secret}`)).toBe("Password=[redacted]");
    expect(redactEvidence("User ID=sa")).toBe("User ID=[redacted]");
  });

  it("redacts a secret that sits inside the kept prefix", () => {
    const secret = "vigilTestDbSecret";
    const line = `SQLSTATE[HY000] mysql://app:${secret}@db.internal/app ${"x".repeat(200)}`;
    const redacted = redactEvidence(line);
    expect(redacted).not.toContain(secret);
    expect(redacted.endsWith("...")).toBe(true);
    expect(redacted.length).toBeLessThanOrEqual(180);
  });

  it("leaves an ordinary sentence alone and still redacts api_key assignments", () => {
    expect(redactEvidence("PHP Version 8.2.34 was announced today.")).toBe("PHP Version 8.2.34 was announced today.");
    expect(redactEvidence(`api_key: "vigilTestKeyPlaceholder1234567890"`)).not.toContain("vigilTestKeyPlaceholder1234567890");
  });
});
