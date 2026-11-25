import Foundation

/// Decodes the fields invariant needs from a raw `audit_token_t`, as delivered in
/// `NEFilterFlow.sourceAppAuditToken` (32 bytes: eight 32-bit values). The layout is the
/// one `audit_token_to_pid()` / `audit_token_to_euid()` read in libbsm: val[1] = euid,
/// val[5] = pid, val[7] = pid version. Parsing it here keeps the extension free of a
/// libbsm link and lets the logic be tested off-Mac.
public struct AuditTokenInfo: Equatable {
    public let pid: Int32
    public let euid: UInt32
    public let pidVersion: Int32

    public init?(_ data: Data) {
        guard data.count >= 32 else { return nil }
        var vals = [UInt32](repeating: 0, count: 8)
        for i in 0..<8 {
            let start = data.startIndex + i * 4
            let b = data[start..<start + 4]
            vals[i] = b.enumerated().reduce(UInt32(0)) { acc, pair in
                acc | (UInt32(pair.element) << (8 * UInt32(pair.offset)))  // little-endian
            }
        }
        euid = vals[1]
        pid = Int32(bitPattern: vals[5])
        pidVersion = Int32(bitPattern: vals[7])
    }

    /// Key for caching per-process lookups: pid alone is reused, pid + version is not.
    public var cacheKey: Int64 { (Int64(pid) << 32) | Int64(UInt32(bitPattern: pidVersion)) }
}
