import Foundation
import Combine

/// Log entry with timestamp
struct LogEntry: Identifiable, Hashable {
    let id = UUID()
    let timestamp: Date
    let message: String
}

/// Observable proxy manager for SwiftUI lifecycle.
/// Flow:
///   1. connect() starts a Go proxy instance (no VK auth happens inside Go).
///   2. Go waits on an internal channel for TURN credentials.
///   3. In parallel, Swift opens a WKWebView to the VK call link; JS hook
///      watches RTCPeerConnection and XHR/fetch responses for TURN creds.
///   4. When JS reports creds, we pass them to Go via VKTurnSubmitTurnCreds.
///   5. Go unblocks, builds the TURN tunnel. WebView closes automatically.
@MainActor
final class ProxyManager: ObservableObject {

    // MARK: - Published State

    @Published private(set) var isRunning = false
    @Published private(set) var statusText = "Disconnected"
    @Published private(set) var logMessages: [LogEntry] = []
    /// When non-nil, ContentView presents the VK captcha WebView sheet.
    @Published var webViewURL: URL? = nil

    // MARK: - Private State

    private var proxyHandle: Int32 = -1
    private var statusTimer: Timer?
    private let maxLogEntries = 200

    private var credsSubmitted = false

    // MARK: - Lifecycle

    deinit {
        Task { @MainActor in
            if self.isRunning {
                await self.disconnect()
            }
        }
    }

    // MARK: - Public API

    func connect(config: ProxyConfig) {
        guard !isRunning && webViewURL == nil else {
            addLog("Already connecting")
            return
        }

        guard let vkURL = URL(string: config.vkLink) else {
            addLog("Invalid VK link")
            return
        }

        addLog("Starting proxy connection...")
        statusText = "Waiting for captcha (browser)"
        credsSubmitted = false

        // 1. Start the Go proxy — it will block waiting for TURN creds.
        Task.detached { [weak self] in
            let handle = VKTurnBridge.startProxy(config: config)
            await MainActor.run {
                guard let self = self else { return }
                if handle >= 0 {
                    self.proxyHandle = handle
                    self.isRunning = true
                    self.addLog("Proxy started with handle \(handle)")
                    self.startStatusPolling()
                } else {
                    self.addLog("Failed to start proxy: handle returned -1")
                    self.statusText = "Connection Failed"
                }
            }
        }

        // 2. Open the WebView so the user can solve VK's captcha.
        webViewURL = vkURL
    }

    @MainActor
    func disconnect() async {
        webViewURL = nil

        guard isRunning else {
            addLog("Not connected")
            statusText = "Disconnected"
            return
        }

        stopStatusPolling()

        let handle = proxyHandle
        addLog("Stopping proxy with handle \(handle)...")

        Task.detached { [weak self] in
            VKTurnBridge.stopProxy(handle: handle)
            await MainActor.run {
                guard let self = self else { return }
                self.proxyHandle = -1
                self.isRunning = false
                self.statusText = "Disconnected"
                self.credsSubmitted = false
                self.addLog("Proxy stopped")
            }
        }
    }

    /// User cancelled the WebView. Stop the Go-side wait too.
    func cancelWebView() {
        webViewURL = nil
        if isRunning && !credsSubmitted {
            Task {
                await disconnect()
            }
        }
    }

    /// JS hook in WebView captured TURN creds. Pass them to Go and close sheet.
    func submitTurnCreds(user: String, credential: String, urls: [String]) {
        guard !credsSubmitted else { return }
        credsSubmitted = true

        // Take the first URL, strip "turn:"/"turns:" scheme and any ?query.
        let server = normalizeTurnURL(urls.first ?? "")
        addLog("Captured TURN creds: user=\(user) server=\(server)")

        let handle = proxyHandle
        Task.detached {
            _ = VKTurnBridge.submitTurnCreds(handle: handle, username: user, credential: credential, server: server)
        }

        // Close WebView.
        webViewURL = nil
    }

    private func normalizeTurnURL(_ raw: String) -> String {
        var s = raw
        if let q = s.firstIndex(of: "?") {
            s = String(s[..<q])
        }
        if s.hasPrefix("turns:") { s.removeFirst("turns:".count) }
        else if s.hasPrefix("turn:") { s.removeFirst("turn:".count) }
        return s
    }

    // MARK: - Status Polling

    private func startStatusPolling() {
        stopStatusPolling()
        statusTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            guard let self = self else { return }
            Task {
                await self.pollStatus()
            }
        }
        Task {
            await pollStatus()
        }
    }

    private func stopStatusPolling() {
        statusTimer?.invalidate()
        statusTimer = nil
    }

    private func pollStatus() async {
        let handle = proxyHandle
        let status: ProxyStatus? = await Task.detached {
            return VKTurnBridge.getStatus(handle: handle)
        }.value

        guard let status = status else {
            statusText = "Status Unknown"
            return
        }

        switch status.state {
        case "running":
            statusText = credsSubmitted ? "Running" : "Waiting for captcha (browser)"
        case "stopped":
            statusText = "Stopped"
            if isRunning {
                addLog("Proxy stopped unexpectedly")
                await disconnect()
            }
        case "error":
            statusText = "Error: \(status.error)"
            if isRunning {
                addLog("Proxy error: \(status.error)")
                await disconnect()
            }
        case "not_found":
            statusText = "Not Found"
            if isRunning {
                addLog("Proxy handle not found")
                await disconnect()
            }
        default:
            statusText = "State: \(status.state)"
        }
    }

    // MARK: - Logging

    private func addLog(_ message: String) {
        let entry = LogEntry(timestamp: Date(), message: message)
        logMessages.append(entry)
        if logMessages.count > maxLogEntries {
            logMessages.removeFirst(logMessages.count - maxLogEntries)
        }
    }
}
