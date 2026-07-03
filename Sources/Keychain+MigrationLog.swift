//
//  Keychain+MigrationLog.swift
//  OneTimePassword
//
//  Copyright (c) 2014-2026 Matt Rubin and the OneTimePassword authors
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

#if os(OSX)

// MARK: - Legacy keychain migration logging (macOS)

private let migrationLogLock = NSLock()
private var migrationLogMessages: [String] = []
private var migrationLogSessionStarted = false
private let migrationLogMaxFileSize = 1024 * 1024 // 1 MB
private let migrationLogTimeFormatter: DateFormatter = {
    let formatter = DateFormatter()
    formatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
    return formatter
}()

private let migrationLogFileURL: URL? = {
    guard let library = FileManager.default.urls(for: .libraryDirectory, in: .userDomainMask).first else {
        return nil
    }
    let logsDirectory = library.appendingPathComponent("Logs", isDirectory: true)
    try? FileManager.default.createDirectory(at: logsDirectory, withIntermediateDirectories: true)
    return logsDirectory.appendingPathComponent("OTPKeychainMigration.log")
}()

/// Logs a legacy migration step to the console, the in-memory log and the persistent file.
func migrationLog(_ message: String) {
    print("CustomDebugLog OTPKeychainMigration: \(message)")
    let line = "\(migrationLogTimeFormatter.string(from: Date())) \(message)"

    migrationLogLock.lock()
    defer { migrationLogLock.unlock() }
    migrationLogMessages.append(line)

    if !migrationLogSessionStarted {
        migrationLogSessionStarted = true
        let processName = ProcessInfo.processInfo.processName
        appendToMigrationLogFile("----- session started (\(processName)) -----")
    }
    appendToMigrationLogFile(line)
}

/// Appends a line to the persistent log file, dropping the oldest half when the file
/// grows over the size limit. Must be called with `migrationLogLock` held.
private func appendToMigrationLogFile(_ line: String) {
    guard let fileURL = migrationLogFileURL, let data = (line + "\n").data(using: .utf8) else {
        return
    }
    guard let handle = try? FileHandle(forWritingTo: fileURL) else {
        try? data.write(to: fileURL)
        return
    }
    defer { handle.closeFile() }
    if handle.seekToEndOfFile() > migrationLogMaxFileSize,
       let contents = try? String(contentsOf: fileURL, encoding: .utf8) {
        let lines = contents.components(separatedBy: "\n")
        let trimmed = lines.suffix(lines.count / 2).joined(separator: "\n")
        try? trimmed.data(using: .utf8)?.write(to: fileURL)
        handle.seekToEndOfFile()
    }
    handle.write(data)
}

extension Keychain {
    /// In-memory log of the legacy migration steps from the current launch, so the host
    /// app can surface it in a debug UI (`print` output is not visible outside Xcode).
    public static var legacyMigrationLog: [String] {
        migrationLogLock.lock()
        defer { migrationLogLock.unlock() }
        return migrationLogMessages
    }

    /// Contents of the persistent migration log file, accumulated across sessions.
    public static var legacyMigrationLogFileContents: String? {
        migrationLogLock.lock()
        defer { migrationLogLock.unlock() }
        guard let fileURL = migrationLogFileURL else {
            return nil
        }
        return try? String(contentsOf: fileURL, encoding: .utf8)
    }

    /// Path of the persistent migration log file, e.g. for sharing along with other logs.
    public static var legacyMigrationLogFilePath: String? {
        migrationLogFileURL?.path
    }
}

#endif
