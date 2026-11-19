import CoreGraphics
import Darwin
import Foundation
import ImageIO
import ScreenCaptureKit
import UniformTypeIdentifiers

private let maximumJPEGBytes = 256 * 1024
private let maximumRequestBytes = 1135

private enum DesktopError: LocalizedError {
    case invalidRequest, displayUnavailable, imageTooLarge, inputUnavailable
    case screenPermission, inputPermission

    var errorDescription: String? {
        switch self {
        case .invalidRequest: return "invalid desktop helper request"
        case .displayUnavailable: return "the main display is unavailable"
        case .imageTooLarge: return "could not encode a JPEG within the desktop frame limit"
        case .inputUnavailable: return "could not create a desktop input event"
        case .screenPermission: return "enable Screen Recording for the desktop helper"
        case .inputPermission: return "enable Accessibility for the desktop helper"
        }
    }
}

private enum Action: UInt8 {
    case capture = 1, click, move, type, key, scroll
}

private struct DisplayGeometry {
    let bounds: CGRect
    let width: Int
    let height: Int

    init(display: CGDirectDisplayID) throws {
        bounds = CGDisplayBounds(display)
        guard bounds.width >= 1, bounds.height >= 1 else { throw DesktopError.displayUnavailable }
        let scale = min(1, 960 / max(bounds.width, bounds.height))
        width = max(1, Int((bounds.width * scale).rounded()))
        height = max(1, Int((bounds.height * scale).rounded()))
    }

    func point(x: Int, y: Int) throws -> CGPoint {
        guard x < width, y < height else { throw DesktopError.invalidRequest }
        return CGPoint(
            x: bounds.minX + (Double(x) + 0.5) * bounds.width / Double(width),
            y: bounds.minY + (Double(y) + 0.5) * bounds.height / Double(height)
        )
    }
}

private actor Screen {
    private var cachedDisplay: CGDirectDisplayID?
    private var cachedBounds: CGRect?
    private var cachedFilter: SCContentFilter?

    func capture() async throws -> Data {
        guard CGPreflightScreenCaptureAccess() else { throw DesktopError.screenPermission }
        do {
            return try await captureMainDisplay()
        } catch {
            // The WindowServer can invalidate filters when the display configuration changes.
            cachedFilter = nil
            throw error
        }
    }

    private func captureMainDisplay() async throws -> Data {
        let displayID = CGMainDisplayID()
        let geometry = try DisplayGeometry(display: displayID)
        let filter: SCContentFilter
        if cachedDisplay == displayID, cachedBounds == geometry.bounds, let cachedFilter {
            filter = cachedFilter
        } else {
            let available = try await SCShareableContent.excludingDesktopWindows(false, onScreenWindowsOnly: true)
            guard let display = available.displays.first(where: { $0.displayID == displayID }) else {
                throw DesktopError.displayUnavailable
            }
            filter = SCContentFilter(display: display, excludingWindows: [])
            cachedDisplay = displayID
            cachedBounds = geometry.bounds
            cachedFilter = filter
        }

        let configuration = SCStreamConfiguration()
        configuration.width = geometry.width
        configuration.height = geometry.height
        configuration.showsCursor = true
        let image = try await SCScreenshotManager.captureImage(contentFilter: filter, configuration: configuration)
        for quality in [0.65, 0.40, 0.20] {
            let output = NSMutableData()
            let settings = [kCGImageDestinationLossyCompressionQuality: quality] as CFDictionary
            guard let jpeg = CGImageDestinationCreateWithData(output, UTType.jpeg.identifier as CFString, 1, nil) else {
                continue
            }
            CGImageDestinationAddImage(jpeg, image, settings)
            if CGImageDestinationFinalize(jpeg), output.length <= maximumJPEGBytes {
                return output as Data
            }
        }
        throw DesktopError.imageTooLarge
    }
}

private func littleEndian16(_ bytes: Data, at i: Int) -> UInt16 {
    UInt16(bytes[i]) | UInt16(bytes[i + 1]) << 8
}

private func postKey(_ code: UInt16, unicode: [UInt16] = []) throws {
    guard let down = CGEvent(keyboardEventSource: nil, virtualKey: code, keyDown: true),
          let up = CGEvent(keyboardEventSource: nil, virtualKey: code, keyDown: false) else {
        throw DesktopError.inputUnavailable
    }
    if !unicode.isEmpty {
        unicode.withUnsafeBufferPointer {
            down.keyboardSetUnicodeString(stringLength: $0.count, unicodeString: $0.baseAddress)
            up.keyboardSetUnicodeString(stringLength: $0.count, unicodeString: $0.baseAddress)
        }
    }
    down.post(tap: .cghidEventTap)
    up.post(tap: .cghidEventTap)
}

private func postInput(_ action: Action, _ request: Data) throws {
    guard CGPreflightPostEventAccess() else { throw DesktopError.inputPermission }
    switch action {
    case .click, .move:
        let click = action == .click
        guard request.count == (click ? 6 : 5), !click || request[5] <= 1 else {
            throw DesktopError.invalidRequest
        }
        let geometry = try DisplayGeometry(display: CGMainDisplayID())
        let point = try geometry.point(x: Int(littleEndian16(request, at: 1)), y: Int(littleEndian16(request, at: 3)))
        if click {
            let right = request[5] == 1
            let button: CGMouseButton = right ? .right : .left
            guard let down = CGEvent(mouseEventSource: nil, mouseType: right ? .rightMouseDown : .leftMouseDown,
                                     mouseCursorPosition: point, mouseButton: button),
                  let up = CGEvent(mouseEventSource: nil, mouseType: right ? .rightMouseUp : .leftMouseUp,
                                   mouseCursorPosition: point, mouseButton: button) else {
                throw DesktopError.inputUnavailable
            }
            down.setIntegerValueField(.mouseEventClickState, value: 1)
            up.setIntegerValueField(.mouseEventClickState, value: 1)
            down.post(tap: .cghidEventTap)
            up.post(tap: .cghidEventTap)
        } else {
            guard let event = CGEvent(mouseEventSource: nil, mouseType: .mouseMoved,
                                      mouseCursorPosition: point, mouseButton: .left) else {
                throw DesktopError.inputUnavailable
            }
            event.post(tap: .cghidEventTap)
        }
    case .type:
        guard request.count > 1, let text = String(bytes: request.dropFirst(), encoding: .utf8) else {
            throw DesktopError.invalidRequest
        }
        for scalar in text.unicodeScalars {
            try postKey(0, unicode: Array(String(scalar).utf16))
        }
    case .key:
        guard request.count == 3 else { throw DesktopError.invalidRequest }
        let key = littleEndian16(request, at: 1)
        guard key <= 127 else { throw DesktopError.invalidRequest }
        try postKey(key)
    case .scroll:
        guard request.count == 5 else { throw DesktopError.invalidRequest }
        let dx = Int32(Int16(bitPattern: littleEndian16(request, at: 1)))
        let dy = Int32(Int16(bitPattern: littleEndian16(request, at: 3)))
        guard let scroll = CGEvent(scrollWheelEvent2Source: nil, units: .pixel, wheelCount: 2,
                                   wheel1: dy, wheel2: dx, wheel3: 0) else {
            throw DesktopError.inputUnavailable
        }
        scroll.post(tap: .cghidEventTap)
    case .capture:
        throw DesktopError.invalidRequest
    }
}

private func readExactly(_ fd: Int32, length: Int) -> Data? {
    var data = Data(count: length)
    return data.withUnsafeMutableBytes { buffer -> Bool in
        guard let base = buffer.baseAddress else { return false }
        var offset = 0
        while offset < length {
            let count = Darwin.read(fd, base + offset, length - offset)
            if count <= 0 { return false }
            offset += count
        }
        return true
    } ? data : nil
}

private func writeAll(_ fd: Int32, _ data: Data) -> Bool {
    data.withUnsafeBytes { buffer in
        guard let base = buffer.baseAddress else { return true }
        var offset = 0
        while offset < buffer.count {
            let count = Darwin.write(fd, base + offset, buffer.count - offset)
            if count <= 0 { return false }
            offset += count
        }
        return true
    }
}

private func writeResponse(_ fd: Int32, ok: Bool, payload: Data = Data()) -> Bool {
    var length = UInt32(1 + payload.count).littleEndian
    var header = withUnsafeBytes(of: &length) { Data($0) }
    header.append(ok ? 0 : 1)
    return writeAll(fd, header) && writeAll(fd, payload)
}

private func servePeer(_ fd: Int32, screen: Screen, inputQueue: DispatchQueue) {
    defer { Darwin.close(fd) }
    while let header = readExactly(fd, length: 4) {
        let size = header.withUnsafeBytes { Int(UInt32(littleEndian: $0.loadUnaligned(as: UInt32.self))) }
        guard (1...maximumRequestBytes).contains(size), let request = readExactly(fd, length: size) else { return }
        do {
            guard let action = Action(rawValue: request[0]) else { throw DesktopError.invalidRequest }
            if action == .capture {
                guard request.count == 1 else { throw DesktopError.invalidRequest }
                // Keep the blocking socket on a GCD worker and ScreenCaptureKit on Swift's executor.
                let done = DispatchSemaphore(value: 0)
                Task.detached {
                    defer { done.signal() }
                    do {
                        let jpeg = try await screen.capture()
                        _ = writeResponse(fd, ok: true, payload: jpeg)
                    } catch {
                        _ = writeResponse(fd, ok: false, payload: Data(error.localizedDescription.utf8.prefix(512)))
                    }
                }
                done.wait()
            } else {
                try inputQueue.sync { try postInput(action, request) }
                if !writeResponse(fd, ok: true) { return }
            }
        } catch {
            if !writeResponse(fd, ok: false, payload: Data(error.localizedDescription.utf8.prefix(512))) {
                return
            }
        }
    }
}

@main
private struct DesktopHelper {
    static func main() {
        let args = CommandLine.arguments
        guard args.count == 2 else { fail("usage: eco-desktop SOCKET | --request-permissions") }
        if args[1] == "--request-permissions" {
            print("Screen Recording: \(CGRequestScreenCaptureAccess())")
            print("Accessibility: \(CGRequestPostEventAccess())")
            return
        }
        eco_install_signals()
        let path = args[1]
        let parent = (path as NSString).deletingLastPathComponent
        guard path.hasPrefix("/"), !path.utf8.contains(0), eco_check_private_dir(parent) == 1 else {
            fail("use an absolute socket path in a private directory owned by this user")
        }
        let lock = eco_lock_local(path + ".lock")
        guard lock >= 0 else { fail("another process owns the desktop socket") }
        defer { Darwin.close(lock) }
        guard eco_prepare_socket(path) == 0 else { fail("cannot prepare the desktop socket") }
        let listener = eco_listen_local(path)
        guard listener >= 0 else { fail("cannot listen on the desktop socket") }
        defer {
            Darwin.close(listener)
            unlink(path)
        }

        let screen = Screen()
        let workers = DispatchQueue.global(qos: .userInitiated)
        let inputQueue = DispatchQueue(label: "eco.desktop.input", qos: .userInteractive)
        let slots = DispatchSemaphore(value: 8)
        while eco_stopping() == 0 {
            guard eco_wait(listener, 250) != 0 else { continue }
            let fd = eco_accept_local(listener)
            guard fd >= 0 else { continue }
            var uid: uid_t = 0
            var gid: gid_t = 0
            let flags = fcntl(fd, F_GETFL)
            guard getpeereid(fd, &uid, &gid) == 0, uid == geteuid(),
                  flags >= 0, fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) == 0,
                  slots.wait(timeout: .now()) == .success else {
                Darwin.close(fd)
                continue
            }
            workers.async {
                defer { slots.signal() }
                servePeer(fd, screen: screen, inputQueue: inputQueue)
            }
        }
    }

    static func fail(_ message: String) -> Never {
        FileHandle.standardError.write(Data("eco-desktop: \(message)\n".utf8))
        exit(125)
    }
}
