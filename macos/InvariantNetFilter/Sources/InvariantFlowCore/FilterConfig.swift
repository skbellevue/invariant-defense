import Foundation

/// Extension settings, delivered as `vendorConfiguration["config"]` (a JSON string) by the
/// host app or by an MDM content-filter payload's VendorConfig. Generate the catalog-mode
/// version with `invariant catalog --format nefilter`.
public struct FilterConfig: Codable, Equatable {
    /// "all": report every outbound flow. "catalog": only flows to `domains` / `ports`
    /// (much lower volume; loses the inventory of unknown destinations and generic beacons).
    public var mode: String
    public var domains: [String]
    public var ports: [Int]
    /// Write JSONL to the extension's app-group container (rotated at `maxFileBytes`).
    public var writeFile: Bool
    /// Emit each record to the unified log (subsystem below), read with `log stream`.
    public var unifiedLog: Bool
    public var maxFileBytes: Int

    public static let subsystem = "com.skbellevue.invariant.netfilter"

    public init(mode: String = "all", domains: [String] = [], ports: [Int] = [], writeFile: Bool = true,
                unifiedLog: Bool = true, maxFileBytes: Int = 50 * 1024 * 1024) {
        self.mode = mode
        self.domains = domains
        self.ports = ports
        self.writeFile = writeFile
        self.unifiedLog = unifiedLog
        self.maxFileBytes = maxFileBytes
    }

    enum CodingKeys: String, CodingKey {
        case mode, domains, ports
        case writeFile = "write_file"
        case unifiedLog = "unified_log"
        case maxFileBytes = "max_file_bytes"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = FilterConfig()
        mode = try c.decodeIfPresent(String.self, forKey: .mode) ?? d.mode
        domains = try c.decodeIfPresent([String].self, forKey: .domains) ?? d.domains
        ports = try c.decodeIfPresent([Int].self, forKey: .ports) ?? d.ports
        writeFile = try c.decodeIfPresent(Bool.self, forKey: .writeFile) ?? d.writeFile
        unifiedLog = try c.decodeIfPresent(Bool.self, forKey: .unifiedLog) ?? d.unifiedLog
        maxFileBytes = try c.decodeIfPresent(Int.self, forKey: .maxFileBytes) ?? d.maxFileBytes
    }

    /// Parse the JSON string from vendorConfiguration; fall back to defaults on any error
    /// so a bad config degrades to "report everything" instead of silencing the sensor.
    public static func from(json: String?) -> FilterConfig {
        guard let json, let data = json.data(using: .utf8),
              let cfg = try? JSONDecoder().decode(FilterConfig.self, from: data) else {
            return FilterConfig()
        }
        return cfg
    }

    /// Should this flow be reported?
    public func shouldReport(host: String?, port: Int?) -> Bool {
        if mode != "catalog" { return true }
        if let port, ports.contains(port) { return true }
        return HostMatcher(domains).matches(host)
    }
}

/// Exact-or-subdomain suffix matching, the same rule as Python's `util.domain_matches`.
public struct HostMatcher {
    private let suffixes: [String]

    public init(_ domains: [String]) {
        suffixes = domains.map {
            var s = $0.lowercased()
            while s.hasPrefix("*.") || s.hasPrefix(".") { s.removeFirst(s.hasPrefix("*.") ? 2 : 1) }
            while s.hasSuffix(".") { s.removeLast() }
            return s
        }.filter { !$0.isEmpty }
    }

    public func matches(_ host: String?) -> Bool {
        guard var h = host?.lowercased(), !h.isEmpty else { return false }
        while h.hasSuffix(".") { h.removeLast() }
        return suffixes.contains { h == $0 || h.hasSuffix("." + $0) }
    }
}
