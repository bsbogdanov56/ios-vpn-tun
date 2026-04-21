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
}

/// Swift wrapper around Go C API for VK TURN proxy
/// Manages C string memory and handle lifecycle
final class VKTurnBridge {

    /// Start a new proxy instance with the given configuration.
    /// The Go side will block waiting for TURN credentials — Swift must call
    /// submitTurnCreds once the WebView captures them.
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

    static func stopProxy(handle: Int32) {
        VKTurnStopProxy(handle)
    }

    static func getStatus(handle: Int32) -> ProxyStatus? {
        guard let cString = VKTurnGetStatus(handle) else {
            return nil
        }

        defer { VKTurnFreeString(cString) }

        let jsonString = String(cString: cString)
        guard let jsonData = jsonString.data(using: .utf8) else {
            return nil
        }

        return try? JSONDecoder().decode(ProxyStatus.self, from: jsonData)
    }

    /// Feed WebView-captured TURN credentials to the proxy instance.
    /// - Returns: true on success, false if handle invalid / already submitted.
    static func submitTurnCreds(handle: Int32, username: String, credential: String, server: String) -> Bool {
        return username.withCString { uPtr in
            credential.withCString { cPtr in
                server.withCString { sPtr in
                    VKTurnSubmitTurnCreds(
                        handle,
                        UnsafeMutablePointer(mutating: uPtr),
                        UnsafeMutablePointer(mutating: cPtr),
                        UnsafeMutablePointer(mutating: sPtr)
                    ) == 0
                }
            }
        }
    }
}
