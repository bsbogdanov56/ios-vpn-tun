import Foundation
import Combine

struct LogEntry: Identifiable, Hashable {
    let id = UUID()
    let timestamp: Date
    let message: String
}

@MainActor
final class ProxyManager: ObservableObject {

    @Published private(set) var isRunning = false
    @Published private(set) var statusText = "Disconnected"
    @Published private(set) var logMessages: [LogEntry] = []
    @Published var captchaImgURL: String? = nil
    @Published private(set) var captchaSid: String? = nil
    @Published var captchaRedirectURL: URL? = nil

    private var proxyHandle: Int32 = -1
    private var statusTimer: Timer?
    private let maxLogEntries = 200
    private var lastCaptchaSid: String? = nil
    /// Set to true right before we submit a captcha answer/token. Tells the
    /// sheet-dismiss handler that the upcoming dismissal is NOT a user cancel.
    private var captchaSubmissionInFlight: Bool = false

    deinit {
        Task { @MainActor in
            if self.isRunning {
                await self.disconnect()
            }
        }
    }

    func connect(config: ProxyConfig) {
        guard !isRunning else {
            addLog("Already connected")
            return
        }
        addLog("Starting proxy connection...")
        statusText = "Connecting..."

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
    }

    @MainActor
    func disconnect() async {
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
                self.captchaImgURL = nil
                self.captchaSid = nil
                self.captchaRedirectURL = nil
                self.lastCaptchaSid = nil
                self.addLog("Proxy stopped")
            }
        }
    }

    func submitCaptchaAnswer(_ answer: String) {
        let handle = proxyHandle
        let trimmed = answer.trimmingCharacters(in: .whitespacesAndNewlines)
        addLog("Submitting captcha: \(trimmed)")
        captchaSubmissionInFlight = true
        Task.detached {
            let ok = VKTurnBridge.submitCaptcha(handle: handle, answer: trimmed)
            await MainActor.run { [weak self] in
                guard let self = self else { return }
                if !ok {
                    self.addLog("Submit captcha: no captcha awaited")
                }
            }
        }
        captchaImgURL = nil
        captchaSid = nil
        captchaRedirectURL = nil
    }

    func submitSuccessToken(_ token: String) {
        let handle = proxyHandle
        addLog("Submitting success_token (len=\(token.count))")
        captchaSubmissionInFlight = true
        Task.detached {
            let ok = VKTurnBridge.submitSuccessToken(handle: handle, token: token)
            await MainActor.run { [weak self] in
                guard let self = self else { return }
                if !ok {
                    self.addLog("Submit success_token: no captcha awaited")
                }
            }
        }
        captchaImgURL = nil
        captchaSid = nil
        captchaRedirectURL = nil
    }

    /// Called from the sheet Binding when the sheet dismisses for any reason.
    /// We only treat it as a real cancel if no submission is in flight.
    func sheetDismissed() {
        if captchaSubmissionInFlight {
            captchaSubmissionInFlight = false
            return
        }
        captchaImgURL = nil
        captchaSid = nil
        captchaRedirectURL = nil
        if isRunning {
            Task { await disconnect() }
        }
    }

    /// Explicit "Отмена" button in the WebView.
    func cancelCaptcha() {
        captchaSubmissionInFlight = false
        captchaImgURL = nil
        captchaSid = nil
        captchaRedirectURL = nil
        if isRunning {
            Task { await disconnect() }
        }
    }

    private func startStatusPolling() {
        stopStatusPolling()
        statusTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            guard let self = self else { return }
            Task { await self.pollStatus() }
        }
        Task { await pollStatus() }
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
            statusText = "Running"
            if captchaImgURL != nil {
                captchaImgURL = nil
                captchaSid = nil
            }
        case "captcha_needed":
            statusText = "Captcha Required"
            let newSid = status.captchaSid
            if newSid != lastCaptchaSid {
                addLog("Captcha required (sid=\(newSid ?? "?"))")
                lastCaptchaSid = newSid
            }
            captchaSid = newSid
            // Prefer WebView flow (id.vk.ru/not_robot_captcha) when available.
            if let redir = status.captchaRedirectURI, let url = URL(string: redir) {
                captchaRedirectURL = url
                captchaImgURL = nil
            } else {
                captchaImgURL = status.captchaImg
                captchaRedirectURL = nil
            }
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

    private func addLog(_ message: String) {
        let entry = LogEntry(timestamp: Date(), message: message)
        logMessages.append(entry)
        if logMessages.count > maxLogEntries {
            logMessages.removeFirst(logMessages.count - maxLogEntries)
        }
    }
}
