import SwiftUI
import UIKit
import WebKit

struct ContentView: View {
    @StateObject private var proxyManager = ProxyManager()
    @State private var vkLink: String = ""
    @State private var wgServer: String = ""

    var body: some View {
        VStack(spacing: 16) {
            TextField("VK Link (e.g. https://vk.com/call/join/...)", text: $vkLink)
                .textFieldStyle(RoundedBorderTextFieldStyle())
                .textInputAutocapitalization(.never)
                .disableAutocorrection(true)

            TextField("WireGuard Server (e.g. 1.2.3.4:51820)", text: $wgServer)
                .textFieldStyle(RoundedBorderTextFieldStyle())
                .textInputAutocapitalization(.never)
                .disableAutocorrection(true)

            Button(action: toggleConnection) {
                Text(proxyManager.isRunning ? "Disconnect" : "Connect")
                    .font(.headline)
                    .foregroundColor(proxyManager.isRunning ? .red : .green)
                    .padding()
                    .frame(maxWidth: .infinity)
                    .background(Color.gray.opacity(0.2))
                    .cornerRadius(8)
            }

            Text(proxyManager.statusText)
                .font(.headline)

            ZStack(alignment: .topTrailing) {
                Color.gray.opacity(0.1)
                    .cornerRadius(8)

                ScrollView {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(proxyManager.logMessages) { log in
                            Text("\(log.timestamp.formatted(date: .omitted, time: .standard)) - \(log.message)")
                                .font(.system(.caption, design: .monospaced))
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .textSelection(.enabled)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(8)
                }

                Button {
                    let text = proxyManager.logMessages
                        .map { "\($0.timestamp.formatted(date: .omitted, time: .standard)) - \($0.message)" }
                        .joined(separator: "\n")
                    UIPasteboard.general.string = text
                } label: {
                    Image(systemName: "doc.on.doc")
                        .font(.footnote)
                        .padding(8)
                        .background(Color.gray.opacity(0.3))
                        .clipShape(Circle())
                }
                .padding(6)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .padding()
        // Primary: WebView with VK not_robot_captcha page (no login, native VK UI).
        .sheet(isPresented: Binding(
            get: { proxyManager.captchaRedirectURL != nil },
            set: { newValue in
                if !newValue {
                    proxyManager.cancelCaptcha()
                }
            }
        )) {
            if let url = proxyManager.captchaRedirectURL {
                NotRobotWebView(
                    url: url,
                    onTokenReceived: { token in
                        proxyManager.submitSuccessToken(token)
                    },
                    onCancel: { proxyManager.cancelCaptcha() }
                )
            }
        }
        // Fallback: plain captcha image modal if VK for some reason didn't
        // give a redirect_uri (rare).
        .sheet(isPresented: Binding(
            get: { proxyManager.captchaImgURL != nil && proxyManager.captchaRedirectURL == nil },
            set: { newValue in
                if !newValue {
                    proxyManager.captchaImgURL = nil
                }
            }
        )) {
            if let imgURL = proxyManager.captchaImgURL {
                CaptchaView(
                    imgURL: imgURL,
                    onSubmit: { answer in
                        proxyManager.submitCaptchaAnswer(answer)
                    }
                )
            }
        }
    }

    private func toggleConnection() {
        if proxyManager.isRunning {
            Task {
                await proxyManager.disconnect()
            }
        } else {
            let config = ProxyConfig(
                peer: wgServer,
                vkLink: vkLink,
                listen: "127.0.0.1:9000",
                streams: 1,
                udp: false
            )
            proxyManager.connect(config: config)
        }
    }
}

struct CaptchaView: View {
    let imgURL: String
    let onSubmit: (String) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var answer: String = ""

    var body: some View {
        VStack(spacing: 20) {
            Text("Введите капчу")
                .font(.title2)
                .bold()
                .padding(.top, 24)

            Text("VK требует подтвердить, что ты не бот.")
                .font(.footnote)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)

            captchaImageView

            TextField("Ответ", text: $answer)
                .textFieldStyle(RoundedBorderTextFieldStyle())
                .textInputAutocapitalization(.never)
                .disableAutocorrection(true)
                .font(.title3)

            HStack(spacing: 12) {
                Button("Отмена") { dismiss() }
                    .foregroundColor(.red)
                    .padding()
                    .frame(maxWidth: .infinity)
                    .background(Color.gray.opacity(0.15))
                    .cornerRadius(8)

                Button("Отправить") {
                    onSubmit(answer)
                    dismiss()
                }
                .foregroundColor(.green)
                .padding()
                .frame(maxWidth: .infinity)
                .background(Color.gray.opacity(0.15))
                .cornerRadius(8)
                .disabled(answer.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }

            Spacer()
        }
        .padding()
    }

    @ViewBuilder
    private var captchaImageView: some View {
        if imgURL.hasPrefix("data:") {
            if let uiImage = decodeDataURLImage(imgURL) {
                Image(uiImage: uiImage)
                    .resizable()
                    .aspectRatio(contentMode: .fit)
                    .frame(maxHeight: 140)
                    .background(Color.white)
                    .cornerRadius(6)
            } else {
                errorImagePlaceholder
            }
        } else {
            AsyncImage(url: URL(string: imgURL)) { phase in
                switch phase {
                case .empty:
                    ProgressView().frame(height: 80)
                case .success(let image):
                    image
                        .resizable()
                        .aspectRatio(contentMode: .fit)
                        .frame(maxHeight: 140)
                        .background(Color.white)
                        .cornerRadius(6)
                case .failure:
                    errorImagePlaceholder
                @unknown default:
                    ProgressView()
                }
            }
        }
    }

    private var errorImagePlaceholder: some View {
        VStack {
            Image(systemName: "exclamationmark.triangle")
                .font(.largeTitle)
                .foregroundColor(.orange)
            Text("Не удалось загрузить картинку")
                .font(.footnote)
        }
        .frame(height: 100)
    }

    private func decodeDataURLImage(_ url: String) -> UIImage? {
        guard let commaIdx = url.firstIndex(of: ",") else { return nil }
        let base64Part = String(url[url.index(after: commaIdx)...])
        guard let data = Data(base64Encoded: base64Part) else { return nil }
        return UIImage(data: data)
    }
}

// MARK: - Not-Robot WebView

/// Loads VK's id.vk.ru/not_robot_captcha page in a WKWebView. The user solves
/// the native VK captcha (checkbox / slider / image); our injected JS hook
/// listens for captchaNotRobot.check XHR responses and extracts success_token.
struct NotRobotWebView: View {
    let url: URL
    let onTokenReceived: (String) -> Void
    let onCancel: () -> Void

    @State private var progress: Double = 0

    var body: some View {
        NavigationView {
            VStack(spacing: 0) {
                if progress > 0 && progress < 1 {
                    ProgressView(value: progress).padding(.horizontal)
                }
                NotRobotWebViewRepresentable(
                    url: url,
                    onTokenReceived: onTokenReceived,
                    progress: $progress
                )
            }
            .navigationBarTitle("Решите капчу VK", displayMode: .inline)
            .navigationBarItems(
                leading: Button("Отмена", action: onCancel)
                    .foregroundColor(.red)
            )
        }
    }
}

private struct NotRobotWebViewRepresentable: UIViewRepresentable {
    let url: URL
    let onTokenReceived: (String) -> Void
    @Binding var progress: Double

    func makeCoordinator() -> Coordinator {
        Coordinator(onTokenReceived: onTokenReceived, progressBinding: $progress)
    }

    func makeUIView(context: Context) -> WKWebView {
        let contentController = WKUserContentController()
        contentController.add(context.coordinator, name: "successToken")

        let hookScript = Self.hookScript()
        contentController.addUserScript(
            WKUserScript(source: hookScript, injectionTime: .atDocumentStart, forMainFrameOnly: false)
        )

        let config = WKWebViewConfiguration()
        config.userContentController = contentController
        config.websiteDataStore = .nonPersistent()

        let webView = WKWebView(frame: .zero, configuration: config)
        webView.navigationDelegate = context.coordinator
        webView.allowsBackForwardNavigationGestures = false
        webView.customUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15"

        webView.load(URLRequest(url: url))
        context.coordinator.observe(webView: webView)
        return webView
    }

    func updateUIView(_ uiView: WKWebView, context: Context) {}

    static func hookScript() -> String {
        return """
        (function() {
            var sent = false;
            function emit(token) {
                if (sent || !token) return;
                sent = true;
                try {
                    window.webkit.messageHandlers.successToken.postMessage(String(token));
                } catch (e) {}
            }

            function scanBody(data) {
                if (!data || typeof data !== 'object') return;
                if (typeof data.success_token === 'string') emit(data.success_token);
                if (data.response) scanBody(data.response);
            }

            // Hook fetch
            var origFetch = window.fetch;
            if (origFetch) {
                window.fetch = function() {
                    var p = origFetch.apply(this, arguments);
                    p.then(function(resp) {
                        return resp.clone().text();
                    }).then(function(text) {
                        try {
                            var data = JSON.parse(text);
                            scanBody(data);
                        } catch (e) {}
                    }).catch(function() {});
                    return p;
                };
            }

            // Hook XMLHttpRequest
            var origOpen = XMLHttpRequest.prototype.open;
            XMLHttpRequest.prototype.open = function() { return origOpen.apply(this, arguments); };
            var origSend = XMLHttpRequest.prototype.send;
            XMLHttpRequest.prototype.send = function() {
                var xhr = this;
                xhr.addEventListener('load', function() {
                    try {
                        var data = JSON.parse(xhr.responseText);
                        scanBody(data);
                    } catch (e) {}
                });
                return origSend.apply(this, arguments);
            };
        })();
        """
    }

    final class Coordinator: NSObject, WKScriptMessageHandler, WKNavigationDelegate {
        let onTokenReceived: (String) -> Void
        private let progressBinding: Binding<Double>
        private var observation: NSKeyValueObservation?

        init(onTokenReceived: @escaping (String) -> Void, progressBinding: Binding<Double>) {
            self.onTokenReceived = onTokenReceived
            self.progressBinding = progressBinding
        }

        func observe(webView: WKWebView) {
            observation = webView.observe(\.estimatedProgress, options: [.new]) { [weak self] webView, _ in
                DispatchQueue.main.async {
                    self?.progressBinding.wrappedValue = webView.estimatedProgress
                }
            }
        }

        func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
            guard message.name == "successToken" else { return }
            if let token = message.body as? String, !token.isEmpty {
                onTokenReceived(token)
            }
        }
    }
}
