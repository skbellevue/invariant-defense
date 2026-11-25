// swift-tools-version:5.9
// InvariantFlowCore: the platform-independent part of the Invariant network filter.
// It builds and tests on Linux and macOS (`swift test`); the Network Extension and the
// host app (see project.yml) link it and add the macOS-only code.
import PackageDescription

let package = Package(
    name: "InvariantFlowCore",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "InvariantFlowCore", targets: ["InvariantFlowCore"]),
    ],
    targets: [
        .target(name: "InvariantFlowCore", path: "Sources/InvariantFlowCore"),
        .testTarget(
            name: "InvariantFlowCoreTests",
            dependencies: ["InvariantFlowCore"],
            path: "Tests/InvariantFlowCoreTests"
        ),
    ]
)
