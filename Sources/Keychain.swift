//
//  Keychain.swift
//  OneTimePassword
//
//  Copyright (c) 2014-2018 Matt Rubin and the OneTimePassword authors
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in all
//  copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//  SOFTWARE.
//

import Foundation

/// The `Keychain`'s shared instance is a singleton which represents the iOS system keychain used
/// to securely store tokens.
public final class Keychain {
    /// The singleton `Keychain` instance.
    public static let sharedInstance = Keychain()

    // MARK: Read

    /// Finds the persistent token with the given identifer, if one exists.
    ///
    /// - parameter identifier: The persistent identifier for the desired token.
    ///
    /// - throws: A `Keychain.Error` if an error occurred.
    /// - returns: The persistent token, or `nil` if no token matched the given identifier.
    public func persistentToken(withIdentifier identifier: Data) throws -> PersistentToken? {
        return try keychainItem(forPersistentRef: identifier).map(PersistentToken.init(keychainDictionary:))
    }

    /// Returns the set of all persistent tokens found in the keychain.
    ///
    /// - throws: A `Keychain.Error` if an error occurred.
    public func allPersistentTokens() throws -> Set<PersistentToken> {
        let allItems = try allKeychainItems()
        // This code intentionally ignores items which fail deserialization, instead opting to return as many readable
        // tokens as possible.
        // TODO: Restore deserialization error handling, in a way that provides info on the failure reason and allows
        //       the caller to choose whether to fail completely or recover some data.
        return Set(allItems.compactMap({ try? PersistentToken(keychainDictionary: $0) }))
    }

    // MARK: Write

    /// Adds the given token to the keychain and returns the persistent token which contains it.
    ///
    /// - parameter token: The token to save to the keychain.
    ///
    /// - throws: A `Keychain.Error` if the token was not added successfully.
    /// - returns: The new persistent token.
    public func add(_ token: Token) throws -> PersistentToken {
        let attributes = try token.keychainAttributes()
        let persistentRef = try addKeychainItem(withAttributes: attributes)
        return PersistentToken(token: token, identifier: persistentRef)
    }

    /// Updates the given persistent token with a new token value.
    ///
    /// - parameter persistentToken: The persistent token to update.
    /// - parameter token: The new token value.
    ///
    /// - throws: A `Keychain.Error` if the update did not succeed.
    /// - returns: The updated persistent token.
    public func update(_ persistentToken: PersistentToken, with token: Token) throws -> PersistentToken {
        let attributes = try token.keychainAttributes()
        try updateKeychainItem(forPersistentRef: persistentToken.identifier,
                               withAttributes: attributes)
        return PersistentToken(token: token, identifier: persistentToken.identifier)
    }

    /// Deletes the given persistent token from the keychain.
    ///
    /// - note: After calling `deletePersistentToken(_:)`, the persistent token's `identifier` is no
    ///         longer valid, and the token should be discarded.
    ///
    /// - parameter persistentToken: The persistent token to delete.
    ///
    /// - throws: A `Keychain.Error` if the deletion did not succeed.
    public func delete(_ persistentToken: PersistentToken) throws {
        try deleteKeychainItem(forPersistentRef: persistentToken.identifier)
    }

    // MARK: Errors

    /// An error type enum representing the various errors a `Keychain` operation can throw.
    public enum Error: Swift.Error {
        /// The keychain operation returned a system error code.
        case systemError(OSStatus)
        /// The keychain operation returned an unexpected type of data.
        case incorrectReturnType
        /// The given token could not be serialized to keychain data.
        case tokenSerializationFailure
    }
}

// MARK: - Private

private let kOTPService = "me.mattrubin.onetimepassword.token"
private let urlStringEncoding = String.Encoding.utf8

/// The UserDefaults key marking that legacy file-based keychain tokens have been
/// migrated to the data protection keychain (macOS only, see `dataProtectionKeychainQuery`).
private let didMigrateTokensToDataProtectionKeychainKey = "OneTimePassword.didMigrateTokensToDataProtectionKeychain"

/// On macOS, routes a keychain query to the data protection keychain — where access is
/// controlled by the app's Team ID / keychain-access-group rather than by the app's code
/// signature. This keeps tokens accessible after the app is re-signed with a different
/// distribution certificate (e.g. switching between App Store and Developer ID builds).
/// On iOS this is already the only keychain, so the flag is a no-op and is omitted.
private func dataProtectionKeychainQuery(_ query: [String: AnyObject]) -> [String: AnyObject] {
    #if os(OSX)
    var query = query
    query[kSecUseDataProtectionKeychain as String] = kCFBooleanTrue
    return query
    #else
    return query
    #endif
}

private extension Token {
    func keychainAttributes() throws -> [String: AnyObject] {
        let url = try self.toURL()
        guard let data = url.absoluteString.data(using: urlStringEncoding) else {
            throw Keychain.Error.tokenSerializationFailure
        }
        return [
            kSecAttrGeneric as String:  data as NSData,
            kSecValueData as String:    generator.secret as NSData,
            kSecAttrService as String:  kOTPService as NSString,
        ]
    }
}

private extension PersistentToken {
    enum DeserializationError: Error {
        case missingData
        case missingSecret
        case missingPersistentRef
        case unreadableData
    }

    init(keychainDictionary: NSDictionary) throws {
        guard let urlData = keychainDictionary[kSecAttrGeneric as String] as? Data else {
            throw DeserializationError.missingData
        }
        guard let secret = keychainDictionary[kSecValueData as String] as? Data else {
            throw DeserializationError.missingSecret
        }
        guard let keychainItemRef = keychainDictionary[kSecValuePersistentRef as String] as? Data else {
            throw DeserializationError.missingPersistentRef
        }
        guard let urlString = String(data: urlData, encoding: urlStringEncoding),
            let url = URL(string: urlString) else {
                throw DeserializationError.unreadableData
        }
        let token = try Token(_url: url, secret: secret)
        self.init(token: token, identifier: keychainItemRef)
    }
}

private func addKeychainItem(withAttributes attributes: [String: AnyObject]) throws -> Data {
    var mutableAttributes = attributes
    mutableAttributes[kSecClass as String] = kSecClassGenericPassword
    mutableAttributes[kSecReturnPersistentRef as String] = kCFBooleanTrue
    // Set a random string for the account name.
    // We never query by or display this value, but the keychain requires it to be unique.
    if mutableAttributes[kSecAttrAccount as String] == nil {
        mutableAttributes[kSecAttrAccount as String] = UUID().uuidString as NSString
    }
    mutableAttributes = dataProtectionKeychainQuery(mutableAttributes)

    var result: AnyObject?
    let resultCode: OSStatus = withUnsafeMutablePointer(to: &result) {
        SecItemAdd(mutableAttributes as CFDictionary, $0)
    }

    guard resultCode == errSecSuccess else {
        throw Keychain.Error.systemError(resultCode)
    }
    guard let persistentRef = result as? Data else {
        throw Keychain.Error.incorrectReturnType
    }
    return persistentRef
}

private func updateKeychainItem(forPersistentRef persistentRef: Data,
                                withAttributes attributesToUpdate: [String: AnyObject]) throws {
    let queryDict = dataProtectionKeychainQuery([
        kSecClass as String:               kSecClassGenericPassword,
        kSecValuePersistentRef as String:  persistentRef as NSData,
    ])

    let resultCode = SecItemUpdate(queryDict as CFDictionary, attributesToUpdate as CFDictionary)

    guard resultCode == errSecSuccess else {
        throw Keychain.Error.systemError(resultCode)
    }
}

private func deleteKeychainItem(forPersistentRef persistentRef: Data) throws {
    let queryDict = dataProtectionKeychainQuery([
        kSecClass as String:               kSecClassGenericPassword,
        kSecValuePersistentRef as String:  persistentRef as NSData,
    ])

    let resultCode = SecItemDelete(queryDict as CFDictionary)

    guard resultCode == errSecSuccess else {
        throw Keychain.Error.systemError(resultCode)
    }
}

private func keychainItem(forPersistentRef persistentRef: Data) throws -> NSDictionary? {
    let queryDict = dataProtectionKeychainQuery([
        kSecClass as String:                kSecClassGenericPassword,
        kSecValuePersistentRef as String:   persistentRef as NSData,
        kSecReturnPersistentRef as String:  kCFBooleanTrue,
        kSecReturnAttributes as String:     kCFBooleanTrue,
        kSecReturnData as String:           kCFBooleanTrue,
        kSecAttrService as String:          kOTPService as NSString,
    ])

    var result: AnyObject?
    let resultCode = withUnsafeMutablePointer(to: &result) {
        SecItemCopyMatching(queryDict as CFDictionary, $0)
    }

    if resultCode == errSecItemNotFound {
        // Not finding any keychain items is not an error in this case. Return nil.
        return nil
    }
    guard resultCode == errSecSuccess else {
        throw Keychain.Error.systemError(resultCode)
    }
    guard let keychainItem = result as? NSDictionary else {
        throw Keychain.Error.incorrectReturnType
    }
    return keychainItem
}

private func allKeychainItems() throws -> [NSDictionary] {
    #if os(OSX)
    // Silent attempt only: items requiring the system permission prompt are skipped here
    // and migrated later via `Keychain.migrateLegacyTokens()`.
    migrateLegacyItemsToDataProtectionKeychainIfNeeded(allowUserInteraction: false)
    #endif

    return try dataProtectionKeychainItems()
}

/// Reads all OTP tokens stored in the data protection keychain.
private func dataProtectionKeychainItems() throws -> [NSDictionary] {
    let queryDict = dataProtectionKeychainQuery([
        kSecClass as String:                kSecClassGenericPassword,
        kSecMatchLimit as String:           kSecMatchLimitAll,
        kSecReturnPersistentRef as String:  kCFBooleanTrue,
        kSecReturnAttributes as String:     kCFBooleanTrue,
        kSecReturnData as String:           kCFBooleanTrue,
        kSecAttrService as String:          kOTPService as NSString,
    ])

    var result: AnyObject?
    let resultCode = withUnsafeMutablePointer(to: &result) {
        SecItemCopyMatching(queryDict as CFDictionary, $0)
    }

    if resultCode == errSecItemNotFound {
        // Not finding any keychain items is not an error in this case. Return an empty array.
        return []
    }
    #if os(OSX)
    if resultCode == errSecParam {
        // Some macOS configurations fail batch reads that include kSecValueData with
        // errSecParam — fall back to fetching refs and reading the items one by one.
        migrationLog("batch items read failed with errSecParam, falling back to per-ref reads")
        return dataProtectionKeychainItemsByRefs()
    }
    #endif
    guard resultCode == errSecSuccess else {
        throw Keychain.Error.systemError(resultCode)
    }
    guard let keychainItems = result as? [NSDictionary] else {
        throw Keychain.Error.incorrectReturnType
    }
    return keychainItems
}

#if os(OSX)

// MARK: - Legacy keychain migration (macOS)

extension Keychain {
    /// Whether some legacy tokens are still waiting to be migrated to the data protection
    /// keychain and the system will show permission prompts for them. A silent migration is
    /// attempted first, so this returns `true` only when the remaining items can't be read
    /// without the user's approval (e.g. after a distribution channel switch).
    public static func legacyMigrationNeedsUserApproval() -> Bool {
        migrateLegacyItemsToDataProtectionKeychainIfNeeded(allowUserInteraction: false)
        let needsApproval = !UserDefaults.standard.bool(forKey: didMigrateTokensToDataProtectionKeychainKey)
        migrationLog("needsUserApproval: \(needsApproval)")
        return needsApproval
    }

    /// Migrates the remaining legacy tokens, allowing the system permission prompts (one per
    /// token). Returns `true` once every legacy token has been migrated. Call
    /// `legacyMigrationNeedsUserApproval()` first and warn the user about the prompts.
    @discardableResult
    public static func migrateLegacyTokens() -> Bool {
        migrateLegacyItemsToDataProtectionKeychainIfNeeded(allowUserInteraction: true)
        let migrated = UserDefaults.standard.bool(forKey: didMigrateTokensToDataProtectionKeychainKey)
        migrationLog("migrateLegacyTokens result: \(migrated)")
        return migrated
    }
}

private let migrationLock = NSLock()

/// Copies OTP tokens saved by previous versions in the legacy file-based keychain into
/// the data protection keychain. Runs once (tracked in UserDefaults) and only in the main
/// app, since extensions can't read the legacy items created by the app itself.
///
/// With `allowUserInteraction: false` the system permission prompts are suppressed:
/// items created by a build signed with a different certificate are skipped and retried
/// later, so app startup never blocks on keychain dialogs.
private func migrateLegacyItemsToDataProtectionKeychainIfNeeded(allowUserInteraction: Bool) {
    migrationLock.lock()
    defer { migrationLock.unlock() }

    let defaults = UserDefaults.standard
    guard !defaults.bool(forKey: didMigrateTokensToDataProtectionKeychainKey) else {
        return
    }
    guard Bundle.main.bundleURL.pathExtension != "appex" else {
        return
    }

    let (refsStatus, legacyRefs) = legacyKeychainRefs()
    if refsStatus == errSecItemNotFound {
        // Nothing stored in the legacy keychain — mark as migrated and stop checking.
        migrationLog("no legacy items found, marking migration as done")
        defaults.set(true, forKey: didMigrateTokensToDataProtectionKeychainKey)
        return
    }
    guard refsStatus == errSecSuccess else {
        migrationLog("legacy refs query failed, status: \(refsStatus)")
        return
    }
    migrationLog("start, allowUserInteraction: \(allowUserInteraction), legacy items: \(legacyRefs.count)")

    if !allowUserInteraction {
        // Deprecated along with the rest of the legacy keychain API, but it's the only way
        // to read legacy items without triggering the system permission prompts.
        SecKeychainSetUserInteractionAllowed(false)
    }
    defer {
        if !allowUserInteraction {
            SecKeychainSetUserInteractionAllowed(true)
        }
    }

    let migratedItems = (try? dataProtectionKeychainItems()) ?? []
    migrationLog("items already in data protection keychain: \(migratedItems.count)")
    var migratedAllItems = true
    for (index, ref) in legacyRefs.enumerated() {
        // Reading the secret of an item created by a build signed with a different
        // certificate triggers the system permission prompt.
        let (readStatus, readItem) = legacyKeychainItem(forPersistentRef: ref)
        guard let item = readItem else {
            if readStatus == errSecParam {
                // The flag-less refs query can also return data protection keychain items,
                // whose refs the legacy engine can't parse (errSecParam). They already live
                // in the new keychain, so they don't need migration and don't block it.
                migrationLog("item \(index): not a legacy item, skipping")
            } else {
                // The read failed (e.g. the user denied the system keychain prompt). Keep
                // the flag unset so this item is retried on a later launch.
                migrationLog("item \(index): read failed, status: \(readStatus)")
                migratedAllItems = false
            }
            continue
        }
        guard let generic = item[kSecAttrGeneric as String] as? Data,
              let secret = item[kSecValueData as String] as? Data else {
            migrationLog("item \(index): missing generic or secret, skipping")
            continue
        }
        // Skip tokens already present in the data protection keychain so retries after a
        // partial failure don't create duplicates. Tokens are compared by both the URL and
        // the secret: tokens re-added for the same account can share the same URL.
        let alreadyMigrated = migratedItems.contains { migrated in
            migrated[kSecAttrGeneric as String] as? Data == generic
                && migrated[kSecValueData as String] as? Data == secret
        }
        if alreadyMigrated {
            migrationLog("item \(index): already migrated, skipping")
            continue
        }
        let attributes: [String: AnyObject] = [
            kSecAttrGeneric as String: generic as NSData,
            kSecValueData as String:   secret as NSData,
            kSecAttrService as String: kOTPService as NSString,
        ]
        do {
            _ = try addKeychainItem(withAttributes: attributes)
            migrationLog("item \(index): migrated")
        } catch {
            migrationLog("item \(index): add failed, error: \(error)")
            migratedAllItems = false
        }
    }
    // Only mark migration complete once every token has been copied, so a denied prompt or
    // a transient failure doesn't permanently leave some tokens behind in the legacy keychain.
    migrationLog("finished, migratedAllItems: \(migratedAllItems)")
    if migratedAllItems {
        defaults.set(true, forKey: didMigrateTokensToDataProtectionKeychainKey)
    }
}

/// Reads the persistent refs of all OTP tokens stored in the legacy file-based keychain
/// (without the data protection flag). Returns the raw `SecItemCopyMatching` status so
/// callers can tell "no items" apart from a failed read. Fetching refs doesn't require
/// access to the items' secrets, so this never triggers the system permission prompt —
/// only the per-item secret reads do.
private func legacyKeychainRefs() -> (status: OSStatus, refs: [Data]) {
    let refsQuery: [String: AnyObject] = [
        kSecClass as String:               kSecClassGenericPassword,
        kSecMatchLimit as String:          kSecMatchLimitAll,
        kSecReturnPersistentRef as String: kCFBooleanTrue,
        kSecAttrService as String:         kOTPService as NSString,
    ]
    var result: AnyObject?
    let status = withUnsafeMutablePointer(to: &result) {
        SecItemCopyMatching(refsQuery as CFDictionary, $0)
    }
    guard status == errSecSuccess, let refs = result as? [Data] else {
        return (status, [])
    }
    return (status, refs)
}

private func legacyKeychainItem(forPersistentRef persistentRef: Data) -> (status: OSStatus, item: NSDictionary?) {
    let queryDict: [String: AnyObject] = [
        kSecClass as String:               kSecClassGenericPassword,
        kSecValuePersistentRef as String:  persistentRef as NSData,
        kSecReturnAttributes as String:    kCFBooleanTrue,
        kSecReturnData as String:          kCFBooleanTrue,
        kSecAttrService as String:         kOTPService as NSString,
    ]
    var result: AnyObject?
    let status = withUnsafeMutablePointer(to: &result) {
        SecItemCopyMatching(queryDict as CFDictionary, $0)
    }
    guard status == errSecSuccess else {
        return (status, nil)
    }
    return (status, result as? NSDictionary)
}

/// Fallback for `dataProtectionKeychainItems()`: fetches the persistent refs first and
/// reads each item individually.
private func dataProtectionKeychainItemsByRefs() -> [NSDictionary] {
    let refsQuery = dataProtectionKeychainQuery([
        kSecClass as String:               kSecClassGenericPassword,
        kSecMatchLimit as String:          kSecMatchLimitAll,
        kSecReturnPersistentRef as String: kCFBooleanTrue,
        kSecAttrService as String:         kOTPService as NSString,
    ])
    var result: AnyObject?
    let status = withUnsafeMutablePointer(to: &result) {
        SecItemCopyMatching(refsQuery as CFDictionary, $0)
    }
    guard status == errSecSuccess, let refs = result as? [Data] else {
        if status != errSecItemNotFound {
            migrationLog("data protection refs query failed, status: \(status)")
        }
        return []
    }
    return refs.compactMap { try? keychainItem(forPersistentRef: $0) }
}

#endif
