import Foundation
import XCTest
@testable import InvariantFlowCore

final class FlowRecordTests: XCTestCase {
    /// tests/fixtures/nefilter_flow.json at the repository root: the contract with Python.
    private func contractFixture() throws -> Data {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()  // InvariantFlowCoreTests
            .deletingLastPathComponent()  // Tests
            .deletingLastPathComponent()  // InvariantNetFilter
            .deletingLastPathComponent()  // macos
            .deletingLastPathComponent()  // repo root
        return try Data(contentsOf: root.appendingPathComponent("tests/fixtures/nefilter_flow.json"))
    }

    /// Parse and re-serialize with sorted keys, so formatting differences do not matter
    /// (works the same with Darwin and swift-corelibs Foundation).
    private func canonical(_ data: Data) throws -> String {
        let obj = try JSONSerialization.jsonObject(with: data)
        let out = try JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys])
        return String(decoding: out, as: UTF8.self)
    }

    func testMatchesPythonContract() throws {
        let record = FlowRecord(
            ts: 1_795_683_600.25, host: "mac-dev-07", user: "uid:501", pid: 7200, ppid: 7100,
            image: "/opt/homebrew/bin/claude", signed: true, dstHost: "api.anthropic.com",
            dstIp: "160.79.104.10", dstPort: 443,
            fields: .init(proto: "tcp", direction: "outbound", flowId: "6F9619FF-8B86-D011-B42D-00C04FC964FF",
                          signingId: "com.anthropic.claude-code", teamId: "ABCDE12345", platformBinary: false))
        XCTAssertEqual(try canonical(Data(try record.jsonLine().utf8)), try canonical(try contractFixture()))
    }

    func testOptionalFieldsAreOmittedNotNull() throws {
        let line = try FlowRecord(ts: 1, host: "h").jsonLine()
        XCTAssertFalse(line.contains("null"))
        XCTAssertTrue(line.contains("\"kind\":\"network_connect\""))
        XCTAssertTrue(line.contains("\"source\":\"nefilter\""))
        XCTAssertFalse(line.contains("\n"))
    }

    func testSlashesAreNotEscaped() throws {
        let line = try FlowRecord(ts: 1, host: "h", image: "/usr/bin/osascript").jsonLine()
        XCTAssertTrue(line.contains("/usr/bin/osascript"))
    }
}

final class AuditTokenTests: XCTestCase {
    func testParsesPidEuidAndVersion() throws {
        var vals: [UInt32] = [0, 501, 20, 501, 20, 4242, 100_001, 7]
        let data = Data(bytes: &vals, count: 32)  // native little-endian, as on Apple silicon and Intel
        let info = try XCTUnwrap(AuditTokenInfo(data))
        XCTAssertEqual(info.pid, 4242)
        XCTAssertEqual(info.euid, 501)
        XCTAssertEqual(info.pidVersion, 7)
    }

    func testRejectsShortTokens() {
        XCTAssertNil(AuditTokenInfo(Data(count: 16)))
    }

    func testCacheKeyDistinguishesPidReuse() throws {
        var a: [UInt32] = [0, 0, 0, 0, 0, 99, 0, 1]
        var b: [UInt32] = [0, 0, 0, 0, 0, 99, 0, 2]
        let ka = try XCTUnwrap(AuditTokenInfo(Data(bytes: &a, count: 32))).cacheKey
        let kb = try XCTUnwrap(AuditTokenInfo(Data(bytes: &b, count: 32))).cacheKey
        XCTAssertNotEqual(ka, kb)
    }

    func testParsesSlicedData() throws {
        var vals: [UInt32] = [0, 0, 0, 0, 0, 77, 0, 0]
        let padded = Data([0xFF, 0xFF]) + Data(bytes: &vals, count: 32)
        let slice = padded[2...]  // non-zero startIndex
        XCTAssertEqual(AuditTokenInfo(slice)?.pid, 77)
    }
}

final class FilterConfigTests: XCTestCase {
    func testDefaultsAndBadJson() {
        XCTAssertEqual(FilterConfig.from(json: nil), FilterConfig())
        XCTAssertEqual(FilterConfig.from(json: "{not json"), FilterConfig())
        XCTAssertEqual(FilterConfig().mode, "all")
    }

    func testCatalogMode() {
        let cfg = FilterConfig.from(json: #"{"mode":"catalog","domains":["api.openai.com","*.huggingface.co"],"ports":[11434]}"#)
        XCTAssertTrue(cfg.shouldReport(host: "api.openai.com", port: 443))
        XCTAssertTrue(cfg.shouldReport(host: "router.huggingface.co", port: 443))
        XCTAssertTrue(cfg.shouldReport(host: nil, port: 11434))
        XCTAssertFalse(cfg.shouldReport(host: "example.com", port: 443))
        XCTAssertFalse(cfg.shouldReport(host: "notapi.openai.com.evil", port: 443))
        XCTAssertTrue(cfg.writeFile && cfg.unifiedLog)  // missing keys keep defaults
    }

    func testAllModeReportsEverything() {
        XCTAssertTrue(FilterConfig().shouldReport(host: nil, port: nil))
    }

    func testHostMatcherNormalization() {
        let m = HostMatcher(["API.OpenAI.com.", ".anthropic.com"])
        XCTAssertTrue(m.matches("api.openai.com."))
        XCTAssertTrue(m.matches("api.anthropic.com"))
        XCTAssertFalse(m.matches("openai.com"))
        XCTAssertFalse(m.matches(""))
    }
}

final class RotatingWriterTests: XCTestCase {
    func testWritesAndRotates() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("flows.jsonl")
        let w = RotatingWriter(url: url, maxBytes: 4096)
        let line = String(repeating: "x", count: 1000)
        for _ in 0..<10 { w.write(line: line) }
        w.flush()
        w.close()
        let current = try String(contentsOf: url, encoding: .utf8)
        let rotated = try String(contentsOf: url.appendingPathExtension("1"), encoding: .utf8)
        XCTAssertLessThanOrEqual(current.utf8.count, 4096)
        XCTAssertLessThanOrEqual(rotated.utf8.count, 4096)
        XCTAssertEqual(w.failures, 0)
        XCTAssertTrue(current.hasSuffix("\n"))
    }
}

final class ExpiringCacheTests: XCTestCase {
    func testCachesUntilExpiry() {
        let cache = ExpiringCache<Int, Int>(ttl: 10, capacity: 8)
        var calls = 0
        let t0 = Date()
        XCTAssertEqual(cache.value(for: 1, now: t0) { calls += 1; return 42 }, 42)
        XCTAssertEqual(cache.value(for: 1, now: t0.addingTimeInterval(5)) { calls += 1; return 0 }, 42)
        XCTAssertEqual(cache.value(for: 1, now: t0.addingTimeInterval(11)) { calls += 1; return 7 }, 7)
        XCTAssertEqual(calls, 2)
    }

    func testCapacityBound() {
        let cache = ExpiringCache<Int, Int>(ttl: 60, capacity: 4)
        for i in 0..<20 { _ = cache.value(for: i) { i } }
        XCTAssertLessThanOrEqual(cache.count, 4)
    }
}
