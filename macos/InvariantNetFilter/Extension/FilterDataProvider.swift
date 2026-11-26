import Foundation
import InvariantFlowCore
import Network
import NetworkExtension
import os

/// Monitor-only content filter: every outbound socket flow is attributed to a process
/// (pid, ppid, executable, code signature) and written as an invariant `network_connect`
/// event. It never blocks: every verdict is `.allow()`, so a bug here cannot take the
/// Mac off the network. Isolation is the job of the response loop (pf, EDR, MDM).
final class FilterDataProvider: NEFilterDataProvider {
    private let log = Logger(subsystem: FilterConfig.subsystem, category: "flows")
    private let control = Logger(subsystem: FilterConfig.subsystem, category: "control")
    private var config = FilterConfig()
    private var writer: RotatingWriter?
    private let identities = ExpiringCache<Int64, ProcessIdentity>(ttl: 300, capacity: 4096)
    private let hostName = ProcessInfo.processInfo.hostName

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        let json = filterConfiguration.vendorConfiguration?["config"] as? String
        config = FilterConfig.from(json: json)
        if config.writeFile, let url = Self.outputURL() {
            writer = RotatingWriter(url: url, maxBytes: config.maxFileBytes)
            control.notice("invariant netfilter writing flows to \(url.path, privacy: .public)")
        }
        control.notice("invariant netfilter starting, mode=\(self.config.mode, privacy: .public)")

        // All outbound TCP and UDP, any address. Inbound is out of scope for the L2 invariant.
        let anyOutbound = NENetworkRule(remoteNetwork: nil, remotePrefix: 0, localNetwork: nil,
                                        localPrefix: 0, protocol: .any, direction: .outbound)
        let settings = NEFilterSettings(rules: [NEFilterRule(networkRule: anyOutbound, action: .filterData)],
                                        defaultAction: .allow)
        apply(settings) { [control] error in
            if let error {
                control.error("apply(settings) failed: \(error.localizedDescription, privacy: .public)")
            }
            completionHandler(error)
        }
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        control.notice("invariant netfilter stopping, reason=\(reason.rawValue)")
        writer?.flush()
        writer?.close()
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let socketFlow = flow as? NEFilterSocketFlow, socketFlow.direction == .outbound else {
            return .allow()
        }
        let (ip, port) = Self.remoteAddress(socketFlow)
        let hostname = socketFlow.remoteHostname ?? flow.url?.host
        guard config.shouldReport(host: hostname, port: port) else { return .allow() }

        var record = FlowRecord(ts: Date().timeIntervalSince1970, host: hostName,
                                dstHost: hostname, dstIp: ip, dstPort: port)
        record.fields.proto = Self.protocolName(socketFlow.socketProtocol)
        record.fields.direction = "outbound"
        record.fields.flowId = flow.identifier.uuidString

        // macOS has no sourceAppIdentifier (iOS only): identity comes from audit tokens.
        // sourceProcessAuditToken (macOS 13+) is the process that opened the socket;
        // sourceAppAuditToken is the responsible app, which differs when a helper or XPC
        // service connects on an app's behalf. Prefer the process, record the app if different.
        let processToken = flow.sourceProcessAuditToken.flatMap { d in AuditTokenInfo(d).map { (d, $0) } }
        let appToken = flow.sourceAppAuditToken.flatMap { d in AuditTokenInfo(d).map { (d, $0) } }
        if let source = processToken ?? appToken {
            let (tokenData, token) = source
            let identity = identities.value(for: token.cacheKey) {
                ProcessIdentity.resolve(auditToken: tokenData, pid: token.pid)
            }
            record.pid = Int(token.pid)
            record.user = "uid:\(token.euid)"
            record.ppid = identity.ppid.map { Int($0) }
            record.image = identity.path
            record.signed = identity.signed
            record.fields.signingId = identity.signingId
            record.fields.teamId = identity.teamId
            record.fields.platformBinary = identity.platformBinary
            record.fields.tokenSource = processToken != nil ? "process" : "app"
            if processToken != nil, let app = appToken?.1, app.pid != token.pid {
                record.fields.appPid = Int(app.pid)
            }
        }
        emit(record)
        return .allow()
    }

    // MARK: - output

    private func emit(_ record: FlowRecord) {
        guard let line = try? record.jsonLine() else { return }
        if config.unifiedLog {
            log.info("\(FlowRecord.logPrefix, privacy: .public)\(line, privacy: .public)")
        }
        writer?.write(line: line)
    }

    /// The extension's app-group container (shared group id from the entitlements). As a
    /// root system extension this resolves under /private/var/root/Library/Group Containers/.
    static func outputURL() -> URL? {
        guard let group = Bundle.main.object(forInfoDictionaryKey: "InvariantAppGroup") as? String,
              let base = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: group) else {
            return nil
        }
        return base.appendingPathComponent("flows.jsonl")
    }

    // MARK: - flow helpers

    static func remoteAddress(_ flow: NEFilterSocketFlow) -> (String?, Int?) {
        if #available(macOS 15.0, *) {
            if case let .hostPort(host, port)? = flow.remoteFlowEndpoint {
                return (hostString(host), Int(port.rawValue))
            }
            return (nil, nil)
        }
        if let ep = flow.remoteEndpoint as? NWHostEndpoint {
            return (ep.hostname, Int(ep.port))
        }
        return (nil, nil)
    }

    static func hostString(_ host: Network.NWEndpoint.Host) -> String {
        switch host {
        case let .ipv4(addr): return "\(addr)"
        case let .ipv6(addr): return "\(addr)"
        case let .name(name, _): return name
        @unknown default: return "\(host)"
        }
    }

    static func protocolName(_ proto: Int32) -> String {
        switch proto {
        case 6: return "tcp"   // IPPROTO_TCP
        case 17: return "udp"  // IPPROTO_UDP
        default: return String(proto)
        }
    }
}
