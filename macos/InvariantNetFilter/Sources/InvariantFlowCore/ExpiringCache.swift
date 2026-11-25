import Foundation

/// Small thread-safe cache with a time-to-live and a capacity bound. Used to avoid
/// re-running code-signing checks for every flow of the same process.
public final class ExpiringCache<Key: Hashable, Value> {
    private struct Entry {
        let value: Value
        let expires: Date
    }

    private var store: [Key: Entry] = [:]
    private let lock = NSLock()
    private let ttl: TimeInterval
    private let capacity: Int

    public init(ttl: TimeInterval, capacity: Int) {
        self.ttl = ttl
        self.capacity = max(1, capacity)
    }

    public func value(for key: Key, now: Date = Date(), compute: () -> Value) -> Value {
        lock.lock()
        if let e = store[key], e.expires > now {
            lock.unlock()
            return e.value
        }
        lock.unlock()
        let v = compute()  // outside the lock: may be slow (Security framework calls)
        lock.lock()
        if store.count >= capacity {
            store = store.filter { $0.value.expires > now }
            if store.count >= capacity { store.removeAll(keepingCapacity: true) }
        }
        store[key] = Entry(value: v, expires: now.addingTimeInterval(ttl))
        lock.unlock()
        return v
    }

    public var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return store.count
    }
}
