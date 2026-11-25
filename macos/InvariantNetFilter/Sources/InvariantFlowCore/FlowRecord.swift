import Foundation

/// One outbound flow, encoded exactly as invariant-defense's normalized `Event`
/// (`kind: network_connect`). The Python side reads these lines with `--format nefilter`
/// or as plain JSONL. Optional values are omitted rather than written as null, matching
/// `Event.to_dict()`. The shape is pinned by tests/fixtures/nefilter_flow.json, which
/// both the Swift and the Python test suites check.
public struct FlowRecord: Encodable, Equatable {
    public var ts: Double
    public var host: String
    public var user: String?
    public var pid: Int?
    public var ppid: Int?
    public var image: String?
    public var signed: Bool?
    public var dstHost: String?
    public var dstIp: String?
    public var dstPort: Int?
    public var fields: Fields

    public struct Fields: Encodable, Equatable {
        public var source: String = "nefilter"
        public var proto: String?
        public var direction: String?
        public var flowId: String?
        public var signingId: String?
        public var teamId: String?
        public var platformBinary: Bool?

        public init(proto: String? = nil, direction: String? = nil, flowId: String? = nil,
                    signingId: String? = nil, teamId: String? = nil, platformBinary: Bool? = nil) {
            self.proto = proto
            self.direction = direction
            self.flowId = flowId
            self.signingId = signingId
            self.teamId = teamId
            self.platformBinary = platformBinary
        }

        enum CodingKeys: String, CodingKey {
            case source
            case proto = "protocol"
            case direction
            case flowId = "flow_id"
            case signingId = "signing_id"
            case teamId = "team_id"
            case platformBinary = "platform_binary"
        }

        public func encode(to encoder: Encoder) throws {
            var c = encoder.container(keyedBy: CodingKeys.self)
            try c.encode(source, forKey: .source)
            try c.encodeIfPresent(proto, forKey: .proto)
            try c.encodeIfPresent(direction, forKey: .direction)
            try c.encodeIfPresent(flowId, forKey: .flowId)
            try c.encodeIfPresent(signingId, forKey: .signingId)
            try c.encodeIfPresent(teamId, forKey: .teamId)
            try c.encodeIfPresent(platformBinary, forKey: .platformBinary)
        }
    }

    public init(ts: Double, host: String, user: String? = nil, pid: Int? = nil, ppid: Int? = nil,
                image: String? = nil, signed: Bool? = nil, dstHost: String? = nil, dstIp: String? = nil,
                dstPort: Int? = nil, fields: Fields = Fields()) {
        self.ts = ts
        self.host = host
        self.user = user
        self.pid = pid
        self.ppid = ppid
        self.image = image
        self.signed = signed
        self.dstHost = dstHost
        self.dstIp = dstIp
        self.dstPort = dstPort
        self.fields = fields
    }

    enum CodingKeys: String, CodingKey {
        case kind, ts, host, user, pid, ppid, image, signed
        case dstHost = "dst_host"
        case dstIp = "dst_ip"
        case dstPort = "dst_port"
        case fields
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode("network_connect", forKey: .kind)
        try c.encode(ts, forKey: .ts)
        try c.encode(host, forKey: .host)
        try c.encodeIfPresent(user, forKey: .user)
        try c.encodeIfPresent(pid, forKey: .pid)
        try c.encodeIfPresent(ppid, forKey: .ppid)
        try c.encodeIfPresent(image, forKey: .image)
        try c.encodeIfPresent(signed, forKey: .signed)
        try c.encodeIfPresent(dstHost, forKey: .dstHost)
        try c.encodeIfPresent(dstIp, forKey: .dstIp)
        try c.encodeIfPresent(dstPort, forKey: .dstPort)
        try c.encode(fields, forKey: .fields)
    }

    /// One JSON object on one line, keys sorted (stable output for diffing and tests).
    public func jsonLine() throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(self)
        return String(decoding: data, as: UTF8.self)
    }

    /// Prefix used in unified-log messages so `invariant stream --format nefilter` can pick
    /// flow records out of `log stream --style ndjson` output.
    public static let logPrefix = "INVFLOW "
}
