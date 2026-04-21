import Foundation

public struct ProxyConfig: Codable {
    let peer: String
    let vkLink: String
    let listen: String
    let streams: Int
    let udp: Bool
}

public struct ProxyStatus: Codable {
    let state: String
    let error: String
    let captchaImg: String?
    let captchaSid: String?
    let captchaRedirectURI: String?

    enum CodingKeys: String, CodingKey {
        case state
        case error
        case captchaImg = "captcha_img"
        case captchaSid = "captcha_sid"
        case captchaRedirectURI = "captcha_redirect_uri"
    }
}

final class VKTurnBridge {
    static func startProxy(config: ProxyConfig) -> Int32 {
        do {
            let jsonData = try JSONEncoder().encode(config)
            guard let jsonString = String(data: jsonData, encoding: .utf8) else { return -1 }
            return jsonString.withCString { configPtr in
                return VKTurnStartProxy(UnsafeMutablePointer(mutating: configPtr))
            }
        } catch {
            return -1
        }
    }

    static func stopProxy(handle: Int32) {
        VKTurnStopProxy(handle)
    }

    static func getStatus(handle: Int32) -> ProxyStatus? {
        guard let cString = VKTurnGetStatus(handle) else { return nil }
        defer { VKTurnFreeString(cString) }
        let jsonString = String(cString: cString)
        guard let jsonData = jsonString.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode(ProxyStatus.self, from: jsonData)
    }

    static func submitCaptcha(handle: Int32, answer: String) -> Bool {
        return answer.withCString { ansPtr in
            return VKTurnSubmitCaptcha(handle, UnsafeMutablePointer(mutating: ansPtr)) == 0
        }
    }

    static func submitSuccessToken(handle: Int32, token: String) -> Bool {
        return token.withCString { tokPtr in
            return VKTurnSubmitSuccessToken(handle, UnsafeMutablePointer(mutating: tokPtr)) == 0
        }
    }
}
