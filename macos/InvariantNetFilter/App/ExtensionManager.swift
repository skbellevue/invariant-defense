import Foundation
import InvariantFlowCore
import NetworkExtension
import SystemExtensions

/// Activates the system extension, then saves and enables the content-filter configuration.
/// The filter configuration carries invariant settings in vendorConfiguration["config"]
/// (JSON), read from /Library/Application Support/Invariant/netfilter.json when present
/// (generate it with `invariant catalog --format nefilter`), else defaults (mode "all").
@MainActor
final class ExtensionManager: NSObject, ObservableObject {
    static let subsystem = FilterConfig.subsystem
    static let configPath = "/Library/Application Support/Invariant/netfilter.json"

    @Published var status = "Unknown"
    @Published var modeDescription = "all outbound flows"

    var onFinish: ((Bool) -> Void)?
    private var wantEnabled = true

    private var extensionIdentifier: String {
        Bundle.main.object(forInfoDictionaryKey: "InvariantExtensionBundleID") as? String
            ?? (Bundle.main.bundleIdentifier ?? "com.skbellevue.invariant.netfilter") + ".extension"
    }

    func refresh() async {
        let mgr = NEFilterManager.shared()
        do {
            try await mgr.loadFromPreferences()
            status = mgr.isEnabled ? "Enabled" : (mgr.providerConfiguration == nil ? "Not installed" : "Disabled")
        } catch {
            status = "Error: \(error.localizedDescription)"
        }
        let cfg = FilterConfig.from(json: Self.configJSON())
        modeDescription = cfg.mode == "catalog"
            ? "catalog: \(cfg.domains.count) domains, \(cfg.ports.count) ports"
            : "all outbound flows"
    }

    func activate() {
        wantEnabled = true
        status = "Requesting system extension activation…"
        let req = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: extensionIdentifier,
                                                             queue: .main)
        req.delegate = self
        OSSystemExtensionManager.shared.submitRequest(req)
    }

    func deactivate() {
        wantEnabled = false
        status = "Disabling filter…"
        Task {
            await setFilter(enabled: false)
            let req = OSSystemExtensionRequest.deactivationRequest(forExtensionWithIdentifier: extensionIdentifier,
                                                                   queue: .main)
            req.delegate = self
            OSSystemExtensionManager.shared.submitRequest(req)
        }
    }

    static func configJSON() -> String? {
        guard let data = FileManager.default.contents(atPath: configPath) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    func setFilter(enabled: Bool) async {
        let mgr = NEFilterManager.shared()
        do {
            try await mgr.loadFromPreferences()
            if enabled {
                let proto = NEFilterProviderConfiguration()
                proto.filterSockets = true
                proto.filterPackets = false
                proto.filterDataProviderBundleIdentifier = extensionIdentifier
                proto.vendorConfiguration = ["config": Self.configJSON() ?? "{}"]
                mgr.providerConfiguration = proto
                mgr.localizedDescription = "Invariant Network Filter"
            }
            mgr.isEnabled = enabled
            try await mgr.saveToPreferences()
            status = enabled ? "Enabled" : "Disabled"
        } catch {
            status = "Filter configuration failed: \(error.localizedDescription)"
        }
        onFinish?(status == "Enabled" || status == "Disabled")
    }
}

extension ExtensionManager: OSSystemExtensionRequestDelegate {
    nonisolated func request(_ request: OSSystemExtensionRequest,
                             actionForReplacingExtension existing: OSSystemExtensionProperties,
                             withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }

    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        Task { @MainActor in
            self.status = "Approve the extension in System Settings › General › Login Items & Extensions › Network Extensions"
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest,
                             didFinishWithResult result: OSSystemExtensionRequest.Result) {
        Task { @MainActor in
            if self.wantEnabled {
                await self.setFilter(enabled: true)
            } else {
                self.status = "Uninstalled"
                self.onFinish?(true)
            }
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        Task { @MainActor in
            self.status = "System extension request failed: \(error.localizedDescription)"
            self.onFinish?(false)
        }
    }
}

/// `--activate` / `--deactivate` without UI, for scripted installs.
enum HeadlessRunner {
    @MainActor static var manager: ExtensionManager?

    static func run(activate: Bool) {
        Task { @MainActor in
            let m = ExtensionManager()
            manager = m
            m.onFinish = { ok in
                print(m.status)
                exit(ok ? 0 : 1)
            }
            activate ? m.activate() : m.deactivate()
        }
    }
}
