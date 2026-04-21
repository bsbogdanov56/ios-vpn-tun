import SwiftUI

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

            ScrollView {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(proxyManager.logMessages) { log in
                        Text("\(log.timestamp.formatted(date: .omitted, time: .standard)) - \(log.message)")
                            .font(.system(.caption, design: .monospaced))
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
                .padding(8)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(Color.gray.opacity(0.1))
            .cornerRadius(8)
        }
        .padding()
        .sheet(isPresented: Binding(
            get: { proxyManager.captchaImgURL != nil },
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

            AsyncImage(url: URL(string: imgURL)) { phase in
                switch phase {
                case .empty:
                    ProgressView()
                        .frame(height: 80)
                case .success(let image):
                    image
                        .resizable()
                        .aspectRatio(contentMode: .fit)
                        .frame(maxHeight: 140)
                        .background(Color.white)
                        .cornerRadius(6)
                case .failure:
                    VStack {
                        Image(systemName: "exclamationmark.triangle")
                            .font(.largeTitle)
                            .foregroundColor(.orange)
                        Text("Не удалось загрузить картинку")
                            .font(.footnote)
                    }
                    .frame(height: 100)
                @unknown default:
                    ProgressView()
                }
            }

            TextField("Ответ", text: $answer)
                .textFieldStyle(RoundedBorderTextFieldStyle())
                .textInputAutocapitalization(.never)
                .disableAutocorrection(true)
                .font(.title3)

            HStack(spacing: 12) {
                Button("Отмена") {
                    dismiss()
                }
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
}
