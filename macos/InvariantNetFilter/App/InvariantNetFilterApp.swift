import SwiftUI

/// Host app for the Invariant network filter. Its only jobs: install/activate the system
/// extension and turn the content filter on or off. Must run from /Applications.
/// Headless use (scripts, MDM): `InvariantNetFilter.app/Contents/MacOS/InvariantNetFilter --activate`
/// or `--deactivate`; it exits when the request completes.
@main
struct InvariantNetFilterApp: App {
    @StateObject private var manager = ExtensionManager()

    init() {
        let args = CommandLine.arguments
        if args.contains("--activate") || args.contains("--deactivate") {
            HeadlessRunner.run(activate: args.contains("--activate"))
        }
    }

    var body: some Scene {
        WindowGroup("Invariant Network Filter") {
            ContentView()
                .environmentObject(manager)
                .frame(minWidth: 520, minHeight: 320)
        }
    }
}

struct ContentView: View {
    @EnvironmentObject var manager: ExtensionManager

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Invariant Network Filter").font(.title2).bold()
            Text("Attributes every outbound connection to the process that made it and reports it to invariant-defense. Monitor-only: it never blocks traffic.")
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            LabeledContent("Status", value: manager.status)
            LabeledContent("Mode", value: manager.modeDescription)
            HStack {
                Button("Install and enable") { manager.activate() }
                    .keyboardShortcut(.defaultAction)
                Button("Disable and uninstall") { manager.deactivate() }
            }
            Text("Read flows: sudo log stream --style ndjson --predicate 'subsystem == \"\(ExtensionManager.subsystem)\"' | invariant stream --format nefilter")
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
            Spacer()
        }
        .padding(24)
        .task { await manager.refresh() }
    }
}
