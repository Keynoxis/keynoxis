// SPDX-License-Identifier: MPL-2.0

import AppKit
import CryptoKit
import Darwin
import Foundation
import IOKit
import LocalAuthentication
import Security
import ServiceManagement

public typealias LifecycleCallback = @convention(c) (Int32) -> Void

private final class KeynoxisLifecycleMonitor {
    private var workspaceObservers: [NSObjectProtocol] = []
    private var distributedObservers: [NSObjectProtocol] = []

    init(callback: @escaping LifecycleCallback) {
        let workspaceCenter = NSWorkspace.shared.notificationCenter
        let distributedCenter = DistributedNotificationCenter.default()

        func observeWorkspace(_ name: NSNotification.Name, event: Int32) {
            workspaceObservers.append(workspaceCenter.addObserver(
                forName: name,
                object: nil,
                queue: .main
            ) { _ in callback(event) })
        }

        func observeDistributed(_ name: String, event: Int32) {
            distributedObservers.append(distributedCenter.addObserver(
                forName: Notification.Name(name),
                object: nil,
                queue: .main
            ) { _ in callback(event) })
        }

        observeDistributed("com.apple.screenIsLocked", event: 1)
        observeDistributed("com.apple.screenIsUnlocked", event: 2)
        observeWorkspace(NSWorkspace.willSleepNotification, event: 3)
        observeWorkspace(NSWorkspace.didWakeNotification, event: 4)
        observeWorkspace(NSWorkspace.sessionDidResignActiveNotification, event: 5)
        observeWorkspace(NSWorkspace.sessionDidBecomeActiveNotification, event: 6)
    }

    deinit {
        let workspaceCenter = NSWorkspace.shared.notificationCenter
        workspaceObservers.forEach(workspaceCenter.removeObserver)
        let distributedCenter = DistributedNotificationCenter.default()
        distributedObservers.forEach(distributedCenter.removeObserver)
    }
}

private var lifecycleMonitor: KeynoxisLifecycleMonitor?
private let securityPolicyService = "app.keynoxis.desktop.security-policy"
private let securityPolicyAccount = "security-settings-v1"

// Reading an IORegistry property does not open the HID interface and therefore
// does not require macOS Input Monitoring permission. LocationID gives local
// builds a stable per-port identity for user-assigned device names.
@_cdecl("keynoxis_yubikey_local_id")
public func keynoxisYubiKeyLocalID(_ registryID: UInt64) -> UInt32 {
    let service = IOServiceGetMatchingService(kIOMainPortDefault, IORegistryEntryIDMatching(registryID))
    guard service != 0 else { return 0 }
    defer { IOObjectRelease(service) }
    guard let value = IORegistryEntryCreateCFProperty(
        service,
        "LocationID" as CFString,
        kCFAllocatorDefault,
        0
    )?.takeRetainedValue() as? NSNumber else { return 0 }
    return value.uint32Value
}

@_cdecl("keynoxis_lifecycle_start")
public func keynoxisLifecycleStart(_ callback: LifecycleCallback?) {
    guard let callback else { return }
    DispatchQueue.main.async {
        lifecycleMonitor = KeynoxisLifecycleMonitor(callback: callback)
    }
}

private func securityPolicyQuery(dataProtection: Bool) -> [CFString: Any] {
    var query: [CFString: Any] = [
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: securityPolicyService,
        kSecAttrAccount: securityPolicyAccount,
    ]
    if dataProtection {
        query[kSecUseDataProtectionKeychain] = true
    }
    return query
}

private func readSecurityPolicy(dataProtection: Bool) -> (OSStatus, Data?) {
    var query = securityPolicyQuery(dataProtection: dataProtection)
    query[kSecReturnData] = true
    query[kSecMatchLimit] = kSecMatchLimitOne
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    return (status, result as? Data)
}

private func writeSecurityPolicy(_ data: Data, dataProtection: Bool) -> OSStatus {
    let query = securityPolicyQuery(dataProtection: dataProtection)
    let update = [kSecValueData: data] as CFDictionary
    var status = SecItemUpdate(query as CFDictionary, update)
    if status == errSecItemNotFound {
        var attributes = query
        attributes[kSecValueData] = data
        if dataProtection {
            attributes[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        }
        status = SecItemAdd(attributes as CFDictionary, nil)
    }
    return status
}

@_cdecl("keynoxis_security_policy_read")
public func keynoxisSecurityPolicyRead(
    output: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    outputLength: UnsafeMutablePointer<Int>,
    errorOutput: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    errorLength: UnsafeMutablePointer<Int>
) -> Int32 {
    var (status, data) = readSecurityPolicy(dataProtection: true)
    if status == errSecMissingEntitlement {
        (status, data) = readSecurityPolicy(dataProtection: false)
    }
    if status == errSecItemNotFound { return 2 }
    guard status == errSecSuccess, let data else {
        let message = SecCopyErrorMessageString(status, nil) as String? ?? "Keychain read failed"
        copyBytes(Data(message.utf8), to: errorOutput, length: errorLength)
        return 1
    }
    copyBytes(data, to: output, length: outputLength)
    return 0
}

@_cdecl("keynoxis_security_policy_write")
public func keynoxisSecurityPolicyWrite(
    bytes: UnsafePointer<UInt8>,
    length: Int,
    errorOutput: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    errorLength: UnsafeMutablePointer<Int>
) -> Int32 {
    let data = Data(bytes: bytes, count: length)
    var status = writeSecurityPolicy(data, dataProtection: true)
    if status == errSecMissingEntitlement {
        status = writeSecurityPolicy(data, dataProtection: false)
    }
    guard status == errSecSuccess else {
        let message = SecCopyErrorMessageString(status, nil) as String? ?? "Keychain write failed"
        copyBytes(Data(message.utf8), to: errorOutput, length: errorLength)
        return 1
    }
    return 0
}

private func touchIDContext() throws -> LAContext {
    let context = LAContext()
    context.touchIDAuthenticationAllowableReuseDuration = 0
    context.localizedCancelTitle = "Cancel"

    var availabilityError: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &availabilityError) else {
        throw availabilityError ?? NSError(
            domain: "Keynoxis",
            code: 2,
            userInfo: [NSLocalizedDescriptionKey: "Touch ID is not available"]
        )
    }

    let completed = DispatchSemaphore(value: 0)
    var authenticated = false
    var authenticationError: Error?
    context.evaluatePolicy(
        .deviceOwnerAuthenticationWithBiometrics,
        localizedReason: "Authorize SSH authentication with Keynoxis"
    ) { success, error in
        authenticated = success
        authenticationError = error
        completed.signal()
    }
    completed.wait()

    guard authenticated else {
        throw authenticationError ?? NSError(
            domain: "Keynoxis",
            code: 3,
            userInfo: [NSLocalizedDescriptionKey: "Touch ID authentication failed"]
        )
    }
    return context
}

private func copyBytes(_ data: Data, to pointer: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>, length: UnsafeMutablePointer<Int>) {
    length.pointee = data.count
    guard !data.isEmpty, let allocation = malloc(data.count)?.assumingMemoryBound(to: UInt8.self) else {
        pointer.pointee = nil
        return
    }
    data.copyBytes(to: allocation, count: data.count)
    pointer.pointee = allocation
}

private func copyError(_ error: Error, to pointer: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>, length: UnsafeMutablePointer<Int>) {
    copyBytes(Data(error.localizedDescription.utf8), to: pointer, length: length)
}

@_cdecl("keynoxis_se_create")
public func keynoxisSECreate(
    encryptedKey: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    encryptedKeyLength: UnsafeMutablePointer<Int>,
    publicKey: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    publicKeyLength: UnsafeMutablePointer<Int>,
    errorOutput: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    errorLength: UnsafeMutablePointer<Int>
) -> Int32 {
    do {
        guard SecureEnclave.isAvailable else {
            throw NSError(domain: "Keynoxis", code: 1, userInfo: [NSLocalizedDescriptionKey: "Secure Enclave is not available on this Mac"])
        }
        var accessControlError: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            &accessControlError
        ) else {
            throw accessControlError?.takeRetainedValue() ?? NSError(
                domain: "Keynoxis",
                code: 4,
                userInfo: [NSLocalizedDescriptionKey: "Could not create Secure Enclave access control"]
            )
        }
        let key = try SecureEnclave.P256.Signing.PrivateKey(
            compactRepresentable: false,
            accessControl: accessControl
        )
        copyBytes(key.dataRepresentation, to: encryptedKey, length: encryptedKeyLength)
        copyBytes(key.publicKey.x963Representation, to: publicKey, length: publicKeyLength)
        return 0
    } catch {
        copyError(error, to: errorOutput, length: errorLength)
        return 1
    }
}

@_cdecl("keynoxis_se_sign")
public func keynoxisSESign(
    encryptedKey: UnsafePointer<UInt8>,
    encryptedKeyLength: Int,
    message: UnsafePointer<UInt8>,
    messageLength: Int,
    signature: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    signatureLength: UnsafeMutablePointer<Int>,
    errorOutput: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    errorLength: UnsafeMutablePointer<Int>
) -> Int32 {
    do {
        let context = try touchIDContext()
        let keyData = Data(bytes: encryptedKey, count: encryptedKeyLength)
        let key = try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: keyData,
            authenticationContext: context
        )
        let messageData = Data(bytes: message, count: messageLength)
        let result = try key.signature(for: messageData)
        copyBytes(result.derRepresentation, to: signature, length: signatureLength)
        return 0
    } catch {
        copyError(error, to: errorOutput, length: errorLength)
        return 1
    }
}

@_cdecl("keynoxis_se_free")
public func keynoxisSEFree(_ pointer: UnsafeMutableRawPointer?) {
    free(pointer)
}

@_cdecl("keynoxis_authorize_touch_id")
public func keynoxisAuthorizeTouchID(
    errorOutput: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    errorLength: UnsafeMutablePointer<Int>
) -> Int32 {
    do {
        _ = try touchIDContext()
        return 0
    } catch {
        copyError(error, to: errorOutput, length: errorLength)
        return 1
    }
}

@_cdecl("keynoxis_authorize_security_settings_change")
public func keynoxisAuthorizeSecuritySettingsChange(
    errorOutput: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    errorLength: UnsafeMutablePointer<Int>
) -> Int32 {
    do {
        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 0
        context.localizedCancelTitle = "Cancel"
        var availabilityError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &availabilityError) else {
            throw availabilityError ?? NSError(domain: "Keynoxis", code: 5, userInfo: [NSLocalizedDescriptionKey: "Touch ID is not available"])
        }
        let completed = DispatchSemaphore(value: 0)
        var authenticated = false
        var authenticationError: Error?
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "Disable a Keynoxis security setting") { success, error in
            authenticated = success
            authenticationError = error
            completed.signal()
        }
        completed.wait()
        guard authenticated else {
            throw authenticationError ?? NSError(domain: "Keynoxis", code: 6, userInfo: [NSLocalizedDescriptionKey: "Touch ID authentication failed"])
        }
        return 0
    } catch {
        copyError(error, to: errorOutput, length: errorLength)
        return 1
    }
}

@_cdecl("keynoxis_autostart_status")
public func keynoxisAutostartStatus() -> Int32 {
    switch SMAppService.mainApp.status {
    case .enabled:
        return 1
    case .requiresApproval:
        return 2
    default:
        return 0
    }
}

@_cdecl("keynoxis_autostart_set")
public func keynoxisAutostartSet(
    enabled: Bool,
    errorOutput: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    errorLength: UnsafeMutablePointer<Int>
) -> Int32 {
    do {
        if enabled {
            if SMAppService.mainApp.status != .enabled {
                try SMAppService.mainApp.register()
            }
        } else if SMAppService.mainApp.status != .notRegistered {
            try SMAppService.mainApp.unregister()
        }
        return 0
    } catch {
        copyError(error, to: errorOutput, length: errorLength)
        return 1
    }
}
