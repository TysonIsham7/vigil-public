import { createHash, X509Certificate } from "node:crypto";
import { describe, expect, it } from "vitest";
import distrusted from "../data/distrusted-cas.json" with { type: "json" };
import { blockedSpkiHashes, disabledReputation, intermediatePems, matchDistrust } from "../src/index.js";

const GO_INTERMEDIATES = [
  "ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105",
  "43bffa19d6ef651451f6841e019931e96f6f2eaeff28ab4b6f1ce4576de2717b",
  "e0254c7fcdc265e2f0f8a428dabb75ab4ae039b4872d62f5ee57f0877d5a8a41",
  "49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f",
  "63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8",
  "5c0660a2b164910d8ff589c18e14552e9e0ec237dcefe2cb736d41a4811f81a0",
  "ec4ffa1ad0ac88081314b7aaffef6a91f97cd57291bb5ba686c5415f5eb4f6b6",
  "92c063d67e8f14db71d288e11266ffdaf69cbf115f7bab14f3bc2f68d25e0e30",
];

describe("distrusted CAs", () => {
  it("blocks the eight leaked intermediates and the ECC root, and records AAA", () => {
    const blocked = new Set(blockedSpkiHashes());
    for (const hash of GO_INTERMEDIATES) expect(blocked.has(hash), hash).toBe(true);
    expect(matchDistrust({ spkiSha256: "8d417db2dd8bf5e3084d1e3f196d583849d81bdd4c00c70b9d39369e96b8c782" })?.name).toContain("ECC");
    expect(matchDistrust({ spkiSha256: "bd153ed7b0434f6886b17bce8bbe84ed340c7132d702a8f4fa318f756ecbd6f3" })).toBeUndefined();
    expect(matchDistrust({ spkiSha256: "c619e4780ed8e0abeda24ad732567de4383a7ea941338f6d1a7d1b49ac792fe9" })).toBeUndefined();
  });

  it("recomputes SPKI and certificate fingerprints from the published PEMs", () => {
    const pems = intermediatePems();
    expect(pems).toHaveLength(8);
    for (const row of pems) {
      const cert = new X509Certificate(row.pem);
      const spki = cert.publicKey.export({ type: "spki", format: "der" });
      expect(createHash("sha256").update(spki).digest("hex")).toBe(row.spkiSha256);
      expect(cert.fingerprint256.replaceAll(":", "").toLowerCase()).toBe(row.sha256);
      expect(row.pem).not.toContain("PRIVATE KEY");
    }
    expect(distrusted.roots.find((root) => root.name === "AAA Certificate Services")?.action).toBe("record-only");
    expect(distrusted.followUps[0]?.after).toBe("2026-11-05");
    expect(distrusted.followUps[0]?.item).toMatch(/emSign ECC Root CA - G3/);
  });

  it("does not send a host to a disabled reputation provider", async () => {
    const provider = disabledReputation("safe-browsing");
    const result = await provider.check({
      host: "user-typed.example",
      registrableDomain: "example",
    });
    const observed = JSON.stringify(result);
    expect(result.status).toBe("not-configured");
    expect(observed).not.toContain("user-typed.example");
  });
});
