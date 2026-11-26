import Foundation

/// Append-only JSONL writer with size-based rotation (current file + one `.1`).
/// All writes go through a serial queue, so it is safe to call from the filter's
/// concurrent flow callbacks. Write failures are counted, never thrown: a telemetry
/// sensor must not take the network filter down with it.
public final class RotatingWriter {
    public let url: URL
    public let maxBytes: Int
    private let queue = DispatchQueue(label: "com.skbellevue.invariant.netfilter.writer")
    private var handle: FileHandle?
    private var size: Int = 0
    public private(set) var failures: Int = 0

    public init(url: URL, maxBytes: Int) {
        self.url = url
        self.maxBytes = max(maxBytes, 4096)
    }

    public func write(line: String) {
        queue.sync { self.append(line + "\n") }
    }

    /// Wait for pending writes (used by tests and on stopFilter).
    public func flush() {
        queue.sync { try? self.handle?.synchronize() }
    }

    public func close() {
        queue.sync {
            try? self.handle?.close()
            self.handle = nil
        }
    }

    private func open() throws {
        let fm = FileManager.default
        try fm.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        if !fm.fileExists(atPath: url.path) {
            fm.createFile(atPath: url.path, contents: nil)
        }
        let h = try FileHandle(forWritingTo: url)
        size = Int(try h.seekToEnd())
        handle = h
    }

    private func rotate() throws {
        try handle?.close()
        handle = nil
        let fm = FileManager.default
        let old = url.appendingPathExtension("1")
        if fm.fileExists(atPath: old.path) { try fm.removeItem(at: old) }
        try fm.moveItem(at: url, to: old)
        try open()
    }

    private func append(_ text: String) {
        let data = Data(text.utf8)
        do {
            if handle == nil { try open() }
            if size + data.count > maxBytes && size > 0 { try rotate() }
            try handle?.write(contentsOf: data)
            size += data.count
        } catch {
            failures += 1
            try? handle?.close()
            handle = nil
        }
    }
}
