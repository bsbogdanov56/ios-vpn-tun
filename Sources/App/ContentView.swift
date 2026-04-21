import SwiftUI
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
                ScrollView {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(proxyManager.logMessages) { log in
                            Text("\(log.timestamp.formatted(date: .omitted, time: .standard)) - \(log.message)")
                                .font(.system(.caption, design: .monospaced))
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .textSelection(.enabled)
                        }
                    }
                    .padding(8)
                }
                .background(Color.gray.opacity(0.1))
                .cornerRadius(8)

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
        .sheet(isPresented: Binding(
            get: { proxyManager.webViewURL != nil },
            set: { newValue in
                if !newValue {
                    proxyManager.cancelWebView()
                }
            }
        )) {
            if let url = proxyManager.webViewURL {
                VKCallWebView(
                    url: url,
                    onCredsReceived: { user, pass, urls in
                        proxyManager.submitTurnCreds(user: user, credential: pass, urls: urls)
                    },
                    onCancel: {
                        proxyManager.cancelWebView()
                    }
                )
            }
        }
    }

    private func toggleConnection() {
        if proxyManager.isRunning || proxyManager.webViewURL != nil {
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

// MARK: - VK Call WebView

/// SwiftUI wrapper around WKWebView that loads the VK call page and
/// intercepts TURN credentials as soon as VK hands them to the web client
/// (either via RTCPeerConnection or via XHR/fetch to calls.okcdn.ru).
struct VKCallWebView: View {
    let url: URL
    let onCredsReceived: (String, String, [String]) -> Void
    let onCancel: () -> Void

    @State private var progress: Double = 0

    var body: some View {
        NavigationView {
            VStack(spacing: 0) {
                if progress > 0 && progress < 1 {
                    ProgressView(value: progress).padding(.horizontal)
                }
                WebViewRepresentable(
                    url: url,
                    onCredsReceived: onCredsReceived,
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

private struct WebViewRepresentable: UIViewRepresentable {
    let url: URL
    let onCredsReceived: (String, String, [String]) -> Void
    @Binding var progress: Double

    func makeCoordinator() -> Coordinator {
        Coordinator(onCredsReceived: onCredsReceived, progressBinding: $progress)
    }

    func makeUIView(context: Context) -> WKWebView {
        let contentController = WKUserContentController()
        contentController.add(context.coordinator, name: "turnCreds")

        let hookScript = Self.hookScript()
        contentController.addUserScript(
            WKUserScript(source: hookScript, injectionTime: .atDocumentStart, forMainFrameOnly: false)
        )

        let config = WKWebViewConfiguration()
        config.userContentController = contentController
        config.websiteDataStore = .nonPersistent()
        config.allowsInlineMediaPlayback = true
        config.mediaTypesRequiringUserActionForPlayback = []

        let webView = WKWebView(frame: .zero, configuration: config)
        webView.navigationDelegate = context.coordinator
        webView.allowsBackForwardNavigationGestures = true
        // Desktop Chrome UA — VK's call web client only renders the "Join"
        // interface in desktop mode. On mobile UA VK redirects to /feed.
        webView.customUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"

        context.coordinator.targetURL = url
        context.coordinator.webView = webView

        webView.load(URLRequest(url: url))

        // KVO for progress
        context.coordinator.observe(webView: webView)

        return webView
    }

    func updateUIView(_ uiView: WKWebView, context: Context) {}

    static func hookScript() -> String {
        return """
        (function() {
            var captured = false;
            function emit(username, credential, urls) {
                if (captured) return;
                if (!username || !credential) return;
                if (!urls || (Array.isArray(urls) && urls.length === 0)) return;
                if (typeof urls === 'string') urls = [urls];
                captured = true;
                try {
                    window.webkit.messageHandlers.turnCreds.postMessage({
                        username: String(username),
                        credential: String(credential),
                        urls: urls.map(String)
                    });
                } catch (e) {}
            }

            function scanIceServers(cfg) {
                if (!cfg || !cfg.iceServers) return;
                for (var i = 0; i < cfg.iceServers.length; i++) {
                    var srv = cfg.iceServers[i];
                    if (!srv) continue;
                    if (srv.username && srv.credential) {
                        var urls = srv.urls || (srv.url ? [srv.url] : []);
                        emit(srv.username, srv.credential, urls);
                        return;
                    }
                }
            }

            var origRTC = window.RTCPeerConnection || window.webkitRTCPeerConnection;
            if (origRTC) {
                var Wrapped = function(cfg) {
                    scanIceServers(cfg);
                    return new origRTC(cfg);
                };
                Wrapped.prototype = origRTC.prototype;
                window.RTCPeerConnection = Wrapped;
                if (window.webkitRTCPeerConnection) { window.webkitRTCPeerConnection = Wrapped; }
            }

            function inspectBody(body) {
                if (!body || typeof body !== 'object') return;
                if (body.turn_server && body.turn_server.username) {
                    var ts = body.turn_server;
                    var urls = ts.urls || (ts.url ? [ts.url] : []);
                    emit(ts.username, ts.credential, urls);
                }
                if (body.response) inspectBody(body.response);
                if (Array.isArray(body.ice_servers)) {
                    scanIceServers({iceServers: body.ice_servers});
                }
            }

            var origFetch = window.fetch;
            if (origFetch) {
                window.fetch = function() {
                    var p = origFetch.apply(this, arguments);
                    try {
                        p.then(function(resp) {
                            return resp.clone().text();
                        }).then(function(text) {
                            try {
                                var data = JSON.parse(text);
                                inspectBody(data);
                            } catch (e) {}
                        }).catch(function() {});
                    } catch (e) {}
                    return p;
                };
            }

            var origOpen = XMLHttpRequest.prototype.open;
            XMLHttpRequest.prototype.open = function() {
                this._vkHookUrl = arguments[1] || '';
                return origOpen.apply(this, arguments);
            };
            var origSend = XMLHttpRequest.prototype.send;
            XMLHttpRequest.prototype.send = function() {
                var xhr = this;
                xhr.addEventListener('load', function() {
                    try {
                        var ct = xhr.getResponseHeader && xhr.getResponseHeader('content-type') || '';
                        if (ct.indexOf('json') === -1 && ct.indexOf('javascript') === -1) return;
                        var data = JSON.parse(xhr.responseText);
                        inspectBody(data);
                    } catch (e) {}
                });
                return origSend.apply(this, arguments);
            };
        })();
        """
    }

    final class Coordinator: NSObject, WKScriptMessageHandler, WKNavigationDelegate {
        let onCredsReceived: (String, String, [String]) -> Void
        private let progressBinding: Binding<Double>
        private var observation: NSKeyValueObservation?
        weak var webView: WKWebView?
        var targetURL: URL?
        private var redirectAttempts = 0

        init(onCredsReceived: @escaping (String, String, [String]) -> Void, progressBinding: Binding<Double>) {
            self.onCredsReceived = onCredsReceived
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
            guard message.name == "turnCreds" else { return }
            guard let dict = message.body as? [String: Any],
                  let username = dict["username"] as? String,
                  let credential = dict["credential"] as? String,
                  let urls = dict["urls"] as? [String] else {
                return
            }
            onCredsReceived(username, credential, urls)
        }

        // If after navigating we end up somewhere other than the call join page
        // (e.g., VK redirected to /feed after login), push back to the original
        // call URL. Retry at most twice to avoid infinite loops.
        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
            guard let current = webView.url, let target = targetURL else { return }

            let currentPath = current.path
            let targetPath = target.path

            // Bail out if we're on the right page (call join) or already on captcha page.
            if currentPath.contains("/call/join/") || currentPath.contains("captcha") || currentPath.contains("not_robot") {
                return
            }

            // If VK bounced us to something else (feed, profile, etc.), redirect back.
            if redirectAttempts < 2 && currentPath != targetPath {
                redirectAttempts += 1
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [weak webView] in
                    webView?.load(URLRequest(url: target))
                }
            }
        }
    }
}
