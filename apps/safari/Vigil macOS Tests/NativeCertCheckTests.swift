import XCTest

final class NativeCertCheckTests: XCTestCase {
    func testPublishedCertificateMatchesTheSharedBlocklist() throws {
        let der = try XCTUnwrap(Data(base64Encoded: DistrustedFixture.derBase64))
        let facts = try XCTUnwrap(CertificateFacts.parse(der: der))
        XCTAssertEqual(facts.spkiSha256, DistrustedFixture.spkiSha256)
        XCTAssertEqual(facts.sha256, DistrustedFixture.sha256)
        XCTAssertEqual(facts.commonName, DistrustedFixture.name)
        XCTAssertFalse(facts.selfSigned)
        XCTAssertEqual(DistrustedBlocklist.match(spkiSha256: facts.spkiSha256, sha256: nil)?.name, DistrustedFixture.name)
    }

    func testRecordOnlyRootsDoNotBlock() {
        XCTAssertFalse(DistrustedBlocklist.recordOnlySpki.isEmpty)
        for hash in DistrustedBlocklist.recordOnlySpki {
            XCTAssertNil(DistrustedBlocklist.match(spkiSha256: hash, sha256: hash))
        }
    }

    func testMessageMustBeOneHttpsHost() {
        XCTAssertEqual(HTTPSHost.host(from: ["url": "https://example.com/"]), "example.com")
        XCTAssertEqual(HTTPSHost.host(from: ["url": "https://Example.COM:443"]), "example.com")
        let rejected = [
            "http://example.com/",
            "https://user:pass@example.com/",
            "https://example.com/path",
            "https://example.com/?q=1",
            "https://example.com/#x",
            "https://example.com:8443/",
            "https://127.0.0.1/",
            "https://localhost/",
            "https://example/",
        ]
        for url in rejected {
            XCTAssertNil(HTTPSHost.host(from: ["url": url]), url)
        }
        XCTAssertNil(HTTPSHost.host(from: ["url": "https://example.com/", "other": "no"]))
        XCTAssertNil(HTTPSHost.host(from: "https://example.com/"))
        XCTAssertNil(HTTPSHost.host(from: nil))
    }

    func testNameMatchingUsesTheLeafSanOrCommonName() {
        let leaf = sample(sanDns: ["*.example.com"], commonName: "ignored.example", selfSigned: false)
        XCTAssertTrue(HTTPSHost.nameMatches(host: "www.example.com", facts: leaf))
        XCTAssertFalse(HTTPSHost.nameMatches(host: "a.b.example.com", facts: leaf))
        let commonOnly = sample(sanDns: [], commonName: "WWW.Example.com", selfSigned: false)
        XCTAssertTrue(HTTPSHost.nameMatches(host: "www.example.com", facts: commonOnly))
    }

    func testSignalsCoverDistrustExpiryNameAndSelfSigned() {
        let now = Date(timeIntervalSince1970: 1_761_000_000)
        let clean = sample(sanDns: ["example.com"], commonName: nil, selfSigned: false)
        XCTAssertEqual(CertSignals.make(host: "example.com", chain: [clean], trustOK: true, now: now).map(\.id), [])

        var distrusted = clean
        distrusted.spkiSha256 = DistrustedFixture.spkiSha256
        let blocked = CertSignals.make(host: "example.com", chain: [distrusted], trustOK: true, now: now)
        XCTAssertEqual(blocked.map(\.id), ["CERT_DISTRUSTED_CA", "TLS_INVALID"])
        XCTAssertEqual(blocked[0].severity, "critical")
        XCTAssertFalse(blocked[0].recommendationOnly)
        XCTAssertTrue(blocked[1].recommendationOnly)

        var expired = clean
        expired.notAfter = now.addingTimeInterval(-10)
        XCTAssertEqual(CertSignals.make(host: "example.com", chain: [expired], trustOK: true, now: now).map(\.id), ["CERT_EXPIRED", "TLS_INVALID"])

        XCTAssertEqual(
            CertSignals.make(host: "other.example", chain: [clean], trustOK: true, now: now).map(\.id),
            ["CERT_HOSTNAME_MISMATCH", "TLS_INVALID"]
        )

        var signed = clean
        signed.selfSigned = true
        XCTAssertEqual(CertSignals.make(host: "example.com", chain: [signed], trustOK: false, now: now).map(\.id), ["CERT_SELF_SIGNED", "TLS_INVALID"])

        let invalid = CertSignals.make(host: "example.com", chain: [clean], trustOK: false, now: now)
        XCTAssertEqual(invalid.map(\.id), ["TLS_INVALID"])
        XCTAssertEqual(invalid[0].severity, "high")
    }

    private func sample(sanDns: [String], commonName: String?, selfSigned: Bool) -> CertificateFacts {
        CertificateFacts(
            spkiSha256: "ab",
            sha256: "cd",
            notBefore: Date(timeIntervalSince1970: 1_700_000_000),
            notAfter: Date(timeIntervalSince1970: 1_900_000_000),
            sanDns: sanDns,
            commonName: commonName,
            selfSigned: selfSigned
        )
    }
}
