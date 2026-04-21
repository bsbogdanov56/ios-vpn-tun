import Foundation

/// Configuration for VK TURN proxy
public struct ProxyConfig: Codable {
    let peer: String
    let vkLink: String
    let listen: String
    let streams: Int
    let udp: Bool
}

/// Status response from VK TURN proxy
public struct ProxyStatus: Codable {
    let state: String
    let error: String
    let captchaImg: String?
    let captchaSid: String?

    enum CodingKeys: String, CodingKey {
        case state
        case error
        case captchaImg = "captcha_img"
        case captchaSid = "captcha_sid"
    }
}

/// Swift wrapper around Go C API for VK TURN proxy
/// Manages C string memory and handle lifecycle
final class VKTurnBridge {

    // MARK: - Public API

    /// Start a new proxy instance with the given configuration
    /// - Parameter config: Proxy configuration
    /// - Returns: Handle (>=0) on success, -1 on error
    static func startProxy(config: ProxyConfig) -> Int32 {
        do {
            let jsonData = try JSONEncoder().encode(config)
            guard let jsonString = String(data: jsonData, encoding: .utf8) else {
                return -1
            }

            return jsonString.withCString { configPtr in
                return VKTurnStartProxy(UnsafeMutablePointer(mutating: configPtr))
            }
        } catch {
            return -1
        }
    }

    /// Stop a running proxy instance
    /// - Parameter handle: Handle returned from startProxy
    static func stopProxy(handle: Int32) {
        VKTurnStopProxy(handle)
    }

    /// Get status of a proxy instance
    /// - Parameter handle: Handle returned from startProxy
    /// - Returns: Status struct or nil on error
    static func getStatus(handle: Int32) -> ProxyStatus? {
        guard let cString = VKTurnGetStatus(handle) else {
            return nil
        }

        defer {
            VKTurnFreeString(cString)
        }

        let jsonString = String(cString: cString)
        guard let jsonData = jsonString.data(using: .utf8) else {
            return nil
        }

        return try? JSONDecoder().decode(ProxyStatus.self, from: jsonData)
    }

    /// Submit a user-entered captcha answer to the Go side.
    /// - Returns: true on success, false if not awaiting a captcha.
    static func submitCaptcha(handle: Int32, answer: String) -> Bool {
        return answer.withCString { ansPtr in
            return VKTurnSubmitCaptcha(handle, UnsafeMutablePointer(mutating: ansPtr)) == 0
        }
    }
}
