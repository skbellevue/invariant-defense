import Darwin
import Foundation
import Security

/// Who is behind a flow: executable path, parent pid and code-signing identity.
/// Resolved once per (pid, pid version) and cached by the provider.
struct ProcessIdentity {
    var path: String?
    var ppid: Int32?
    var signed: Bool?
    var signingId: String?
    var teamId: String?
    var platformBinary: Bool?

    static func resolve(auditToken: Data, pid: Int32) -> ProcessIdentity {
        var id = ProcessIdentity()
        id.path = executablePath(pid: pid)
        id.ppid = parentPid(pid: pid)
        signingInfo(auditToken: auditToken, into: &id)
        return id
    }

    static func executablePath(pid: Int32) -> String? {
        let size = 4 * Int(MAXPATHLEN)  // PROC_PIDPATHINFO_MAXSIZE
        var buffer = [CChar](repeating: 0, count: size)
        let n = proc_pidpath(pid, &buffer, UInt32(size))
        guard n > 0 else { return nil }
        return String(cString: buffer)
    }

    static func parentPid(pid: Int32) -> Int32? {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.stride)
        let n = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size)
        guard n == size else { return nil }
        return Int32(bitPattern: info.pbi_ppid)
    }

    /// Code signature of the *running* process, looked up by audit token (immune to pid reuse).
    /// signed = true for platform binaries and valid non-ad-hoc signatures; false for
    /// invalid or ad-hoc signatures, the usual state of dropped malware.
    static func signingInfo(auditToken: Data, into id: inout ProcessIdentity) {
        var code: SecCode?
        let attrs = [kSecGuestAttributeAudit: auditToken] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attrs, [], &code) == errSecSuccess, let code else {
            return
        }
        let valid = SecCodeCheckValidity(code, [], nil) == errSecSuccess

        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else {
            id.signed = valid ? nil : false
            return
        }
        var infoRef: CFDictionary?
        let flags = SecCSFlags(rawValue: kSecCSSigningInformation)
        guard SecCodeCopySigningInformation(staticCode, flags, &infoRef) == errSecSuccess,
              let info = infoRef as? [String: Any] else {
            id.signed = valid ? nil : false
            return
        }
        id.signingId = info[kSecCodeInfoIdentifier as String] as? String
        id.teamId = info[kSecCodeInfoTeamIdentifier as String] as? String
        id.platformBinary = (info[kSecCodeInfoPlatformIdentifier as String] as? NSNumber).map { $0.intValue != 0 }

        let csFlags = (info[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value ?? 0
        let adhoc = csFlags & 0x0000_0002 != 0  // CS_ADHOC
        if id.platformBinary == true {
            id.signed = true
        } else if !valid || adhoc {
            id.signed = false
        } else {
            id.signed = id.teamId != nil ? true : nil
        }
    }
}
