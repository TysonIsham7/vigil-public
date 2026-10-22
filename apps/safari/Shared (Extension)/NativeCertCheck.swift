import CryptoKit
import Foundation
import Security

private let vigilPosix = Locale(identifier: "en_US_POSIX")

private func vigilFold(_ value: String) -> String {
    value.lowercased(with: vigilPosix)
}

struct CertificateFacts: Equatable {
    var spkiSha256: String
    var sha256: String
    var notBefore: Date
    var notAfter: Date
    var sanDns: [String]
    var commonName: String?
    var selfSigned: Bool
}

struct NativeSignal: Equatable {
    var id: String
    var severity: String
    var recommendationOnly: Bool
    var title: String
    var summary: String
    var confidence: String

    var dictionary: [String: Any] {
        [
            "id": id,
            "severity": severity,
            "recommendationOnly": recommendationOnly,
            "title": title,
            "summary": summary,
            "confidence": confidence,
        ]
    }
}

enum FetchResult {
    case transportFailure
    case chain([SecCertificate])
}

/// The message is untrusted. Only an https URL whose host is a DNS name is accepted, and the only connection is to that host.
enum NativeCertCheck {
    static let timeout: TimeInterval = 1.6

    static func respond(to message: Any?) async -> [String: Any] {
        guard let host = HTTPSHost.host(from: message) else {
            return ["error": "rejected"]
        }
        switch await ChainFetcher.fetch(host: host, timeout: timeout) {
        case .transportFailure:
            return ["error": "unavailable"]
        case .chain(let certificates):
            let parsed = certificates.compactMap { CertificateFacts.parse(der: SecCertificateCopyData($0) as Data) }
            if parsed.isEmpty || parsed.count != certificates.count {
                return verdict(host: host, signals: [CertSignals.unreadable()])
            }
            let trustOK = evaluateTrust(certificates: certificates, host: host)
            return verdict(host: host, signals: CertSignals.make(host: host, chain: parsed, trustOK: trustOK, now: Date()))
        }
    }

    static func verdict(host: String, signals: [NativeSignal]) -> [String: Any] {
        [
            "host": host,
            "intelVersion": DistrustedBlocklist.intelVersion,
            "coverage": "full",
            "signals": signals.map(\.dictionary),
        ]
    }

    static func evaluateTrust(certificates: [SecCertificate], host: String) -> Bool {
        let policy = SecPolicyCreateSSL(true, host as CFString)
        var trust: SecTrust?
        guard SecTrustCreateWithCertificates(certificates as CFArray, policy, &trust) == errSecSuccess, let trust else {
            return false
        }
        SecTrustSetNetworkFetchAllowed(trust, false)
        var error: CFError?
        return SecTrustEvaluateWithError(trust, &error)
    }
}

enum HTTPSHost {
    static func host(from message: Any?) -> String? {
        guard let fields = message as? [String: Any], fields.count == 1, let url = fields["url"] as? String else {
            return nil
        }
        return host(in: url)
    }

    static func host(in urlString: String) -> String? {
        guard urlString.count < 300, urlString.hasPrefix("https://") else { return nil }
        let rest = urlString.dropFirst("https://".count)
        if rest.contains("@") || rest.contains("?") || rest.contains("#") || rest.contains("\\") { return nil }
        let pieces = rest.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        guard let hostPort = pieces.first else { return nil }
        if pieces.count == 2 && !pieces[1].isEmpty { return nil }
        let host: String
        if hostPort.hasSuffix(":443") {
            host = String(hostPort.dropLast(4))
        } else if hostPort.contains(":") {
            return nil
        } else {
            host = String(hostPort)
        }
        let normalized = vigilFold(host)
        guard isDnsHost(normalized) else { return nil }
        return normalized
    }

    static func nameMatches(host: String, facts: CertificateFacts) -> Bool {
        let name = vigilFold(host).trimmingCharacters(in: CharacterSet(charactersIn: "."))
        let patterns = facts.sanDns.isEmpty ? (facts.commonName.map { vigilFold($0) } ?? []) : facts.sanDns
        return patterns.contains { dnsMatches(host: name, pattern: $0) }
    }

    private static func dnsMatches(host: String, pattern: String) -> Bool {
        let pattern = vigilFold(pattern).trimmingCharacters(in: CharacterSet(charactersIn: "."))
        if pattern.hasPrefix("*.") {
            let rest = String(pattern.dropFirst())
            let prefix = host.hasSuffix(rest) ? String(host.dropLast(rest.count)) : nil
            return prefix != nil && prefix?.isEmpty == false && prefix?.contains(".") == false
        }
        return host == pattern
    }

    private static func isDnsHost(_ host: String) -> Bool {
        if host.isEmpty || host.count > 253 { return false }
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        if labels.count < 2 { return false }
        if labels.allSatisfy({ !$0.isEmpty && $0.allSatisfy(\.isNumber) }) { return false }
        return labels.allSatisfy { label in
            if label.isEmpty || label.count > 63 { return false }
            if label.hasPrefix("-") || label.hasSuffix("-") { return false }
            return label.allSatisfy { $0.isLetter || $0.isNumber || $0 == "-" }
        }
    }
}

enum CertSignals {
    static func make(host: String, chain: [CertificateFacts], trustOK: Bool, now: Date) -> [NativeSignal] {
        guard let leaf = chain.first else { return [unreadable()] }
        var signals: [NativeSignal] = []
        var names: [String] = []
        for facts in chain {
            guard let hit = DistrustedBlocklist.match(spkiSha256: facts.spkiSha256, sha256: facts.sha256) else { continue }
            if !names.contains(hit.name) { names.append(hit.name) }
        }
        if !names.isEmpty {
            signals.append(critical(
                id: "CERT_DISTRUSTED_CA",
                title: "Certificate chain contains a distrusted key",
                summary: "The chain includes \(names.joined(separator: ", "))."
            ))
        }
        let expired = leaf.notAfter < now
        if expired {
            signals.append(critical(
                id: "CERT_EXPIRED",
                title: "Certificate is expired",
                summary: "The leaf certificate expired on \(iso8601(leaf.notAfter))."
            ))
        }
        let namesMatch = HTTPSHost.nameMatches(host: host, facts: leaf)
        if !namesMatch {
            signals.append(critical(
                id: "CERT_HOSTNAME_MISMATCH",
                title: "Certificate name does not match the host",
                summary: "The certificate presented for \(host) does not list that name."
            ))
        }
        if leaf.selfSigned {
            signals.append(critical(
                id: "CERT_SELF_SIGNED",
                title: "Leaf certificate is self-signed",
                summary: "The server certificate is signed by its own key and that key is not a pinned root."
            ))
        }
        let authorized = trustOK && names.isEmpty && !expired && namesMatch && !leaf.selfSigned && now >= leaf.notBefore
        if !authorized {
            signals.append(NativeSignal(
                id: "TLS_INVALID",
                severity: "high",
                recommendationOnly: true,
                title: "TLS certificate did not validate",
                summary: trustOK
                    ? "The certificate was not authorized."
                    : "The certificate was not authorized by the system trust evaluation.",
                confidence: "high"
            ))
        }
        return signals
    }

    static func unreadable() -> NativeSignal {
        NativeSignal(
            id: "TLS_INVALID",
            severity: "high",
            recommendationOnly: true,
            title: "TLS certificate did not validate",
            summary: "A certificate in the chain could not be read.",
            confidence: "high"
        )
    }

    private static func critical(id: String, title: String, summary: String) -> NativeSignal {
        NativeSignal(id: id, severity: "critical", recommendationOnly: false, title: title, summary: summary, confidence: "high")
    }

    private static func iso8601(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        return formatter.string(from: date)
    }
}

extension CertificateFacts {
    static func parse(der: Data) -> CertificateFacts? {
        let bytes = [UInt8](der)
        guard let cert = DER.read(bytes, 0), cert.tag == 0x30, cert.offset == 0, cert.end == bytes.count else { return nil }
        guard let outer = DER.children(bytes, cert), let tbs = outer.first, tbs.tag == 0x30 else { return nil }
        guard let fields = DER.children(bytes, tbs), fields.count >= 6 else { return nil }
        let index = fields[0].tag == 0xa0 ? 1 : 0
        guard index + 5 < fields.count else { return nil }
        let issuer = fields[index + 2]
        let validity = fields[index + 3]
        let subject = fields[index + 4]
        let spki = fields[index + 5]
        guard validity.tag == 0x30, spki.tag == 0x30, let times = DER.children(bytes, validity), times.count >= 2 else { return nil }
        guard let notBefore = DER.time(bytes, times[0]), let notAfter = DER.time(bytes, times[1]) else { return nil }
        let spkiBytes = Data(bytes[spki.offset..<spki.end])
        return CertificateFacts(
            spkiSha256: DER.sha256(spkiBytes),
            sha256: DER.sha256(der),
            notBefore: notBefore,
            notAfter: notAfter,
            sanDns: DER.sanDns(bytes, fields),
            commonName: DER.commonNames(bytes, subject).first,
            selfSigned: Data(bytes[issuer.offset..<issuer.end]) == Data(bytes[subject.offset..<subject.end])
        )
    }
}

private enum DER {
    struct TLV {
        let tag: UInt8
        let offset: Int
        let start: Int
        let end: Int
    }

    static let sanOID: [UInt8] = [0x55, 0x1d, 0x11]
    static let cnOID: [UInt8] = [0x55, 0x04, 0x03]

    static func read(_ bytes: [UInt8], _ offset: Int) -> TLV? {
        if offset < 0 || offset + 2 > bytes.count { return nil }
        let tag = bytes[offset]
        var length = Int(bytes[offset + 1])
        var header = 2
        if length & 0x80 != 0 {
            let count = length & 0x7f
            if count == 0 || count > 3 || offset + 2 + count > bytes.count { return nil }
            length = 0
            for index in 0..<count {
                length = (length * 256) + Int(bytes[offset + 2 + index])
            }
            header = 2 + count
        }
        let start = offset + header
        let end = start + length
        if end > bytes.count { return nil }
        return TLV(tag: tag, offset: offset, start: start, end: end)
    }

    static func children(_ bytes: [UInt8], _ tlv: TLV) -> [TLV]? {
        var out: [TLV] = []
        var cursor = tlv.start
        while cursor < tlv.end {
            guard let child = read(bytes, cursor), child.end > cursor else { return nil }
            out.append(child)
            cursor = child.end
        }
        if cursor != tlv.end { return nil }
        return out
    }

    static func time(_ bytes: [UInt8], _ tlv: TLV) -> Date? {
        guard let text = String(bytes: bytes[tlv.start..<tlv.end], encoding: .ascii) else { return nil }
        let head = text.split(separator: ".").first.map(String.init) ?? text
        let digits = head.replacingOccurrences(of: "Z", with: "").replacingOccurrences(of: "+", with: " ").split(separator: " ").first.map(String.init) ?? head
        let values = digits.filter(\.isNumber)
        let year: Int
        let rest: Substring
        if tlv.tag == 0x17 && values.count >= 12 {
            let yy = Int(values.prefix(2)) ?? 0
            year = yy >= 50 ? 1900 + yy : 2000 + yy
            rest = values.dropFirst(2)
        } else if tlv.tag == 0x18 && values.count >= 14 {
            year = Int(values.prefix(4)) ?? 0
            rest = values.dropFirst(4)
        } else {
            return nil
        }
        guard rest.count >= 10 else { return nil }
        var parts = DateComponents()
        parts.calendar = Calendar(identifier: .gregorian)
        parts.timeZone = TimeZone(secondsFromGMT: 0)
        parts.year = year
        parts.month = Int(rest.prefix(2))
        parts.day = Int(rest.dropFirst(2).prefix(2))
        parts.hour = Int(rest.dropFirst(4).prefix(2))
        parts.minute = Int(rest.dropFirst(6).prefix(2))
        parts.second = Int(rest.dropFirst(8).prefix(2))
        return parts.date
    }

    static func sanDns(_ bytes: [UInt8], _ fields: [TLV]) -> [String] {
        guard let wrapper = fields.first(where: { $0.tag == 0xa3 }), let sequence = read(bytes, wrapper.start), sequence.tag == 0x30 else {
            return []
        }
        var names: [String] = []
        for ext in children(bytes, sequence) ?? [] {
            guard let parts = children(bytes, ext), parts.count >= 2 else { continue }
            let oid = Array(bytes[parts[0].start..<parts[0].end])
            if oid != sanOID { continue }
            let octet = parts[parts.count - 1]
            guard octet.tag == 0x04, let general = read(bytes, octet.start) else { continue }
            for name in (children(bytes, general) ?? []) where name.tag == 0x82 {
                guard let dns = String(bytes: bytes[name.start..<name.end], encoding: .ascii) else { continue }
                names.append(vigilFold(dns).trimmingCharacters(in: CharacterSet(charactersIn: ".")))
            }
        }
        return names
    }

    static func commonNames(_ bytes: [UInt8], _ name: TLV) -> [String] {
        var found: [String] = []
        for rdn in children(bytes, name) ?? [] {
            for attr in children(bytes, rdn) ?? [] {
                guard let parts = children(bytes, attr), parts.count >= 2 else { continue }
                let oid = Array(bytes[parts[0].start..<parts[0].end])
                if oid != cnOID { continue }
                if let text = String(bytes: bytes[parts[1].start..<parts[1].end], encoding: .utf8) {
                    found.append(text)
                }
            }
        }
        return found
    }

    static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

final class ChainFetcher: NSObject, URLSessionTaskDelegate {
    private let host: String
    private let continuation: CheckedContinuation<FetchResult, Never>
    private var session: URLSession?
    private var certificates: [SecCertificate] = []
    private var sawTrust = false
    private var finished = false

    static func fetch(host: String, timeout: TimeInterval) async -> FetchResult {
        await withCheckedContinuation { continuation in
            let fetcher = ChainFetcher(host: host, continuation: continuation)
            fetcher.start(timeout: timeout)
        }
    }

    private init(host: String, continuation: CheckedContinuation<FetchResult, Never>) {
        self.host = host
        self.continuation = continuation
    }

    private func start(timeout: TimeInterval) {
        var parts = URLComponents()
        parts.scheme = "https"
        parts.host = host
        parts.path = "/"
        guard let url = parts.url else {
            finish(.transportFailure)
            return
        }
        let config = URLSessionConfiguration.ephemeral
        config.connectionProxyDictionary = [:]
        config.timeoutIntervalForRequest = timeout
        config.timeoutIntervalForResource = timeout
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.urlCache = nil
        config.httpShouldSetCookies = false
        config.httpCookieAcceptPolicy = .never
        config.waitsForConnectivity = false
        let session = URLSession(configuration: config, delegate: self, delegateQueue: nil)
        self.session = session
        session.dataTask(with: url).resume()
    }

    private func finish(_ result: FetchResult) {
        if finished { return }
        finished = true
        session?.invalidateAndCancel()
        session = nil
        continuation.resume(returning: result)
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        defer { completionHandler(.cancelAuthenticationChallenge, nil) }
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              vigilFold(challenge.protectionSpace.host) == host,
              let trust = challenge.protectionSpace.serverTrust else { return }
        certificates = SecTrustCopyCertificateChain(trust) as? [SecCertificate] ?? []
        sawTrust = true
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        if sawTrust {
            finish(.chain(certificates))
        } else {
            finish(.transportFailure)
        }
    }
}
