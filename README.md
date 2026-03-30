# VK Turn Proxy for iOS

An iOS port of [vk-turn-proxy](https://github.com/cacggghp/vk-turn-proxy). Tunnels WireGuard traffic through VK call TURN servers to bypass network restrictions.

## How It Works

```
WireGuard App (127.0.0.1:9000) → VK Turn Proxy → VK TURN Server → Your WireGuard Server
```

No extra servers or VPS needed. The app runs a local UDP proxy on your iPhone. You point the WireGuard iOS app at it, and your traffic is relayed through VK's TURN infrastructure directly to your remote WireGuard server.

## Download

**[Download VKTurnProxy.ipa from Releases](https://github.com/kusha/ios-vpn-tun/releases/latest)**

## Quick Start

1. **Install** the IPA via [AltStore](https://altstore.io/) or [Sideloadly](https://sideloadly.io/)
2. **Open VK Turn Proxy** and enter:
   - **VK Link** — a VK call join link (e.g. `https://vk.com/call/join/...`)
   - **WireGuard Server** — your remote WireGuard server IP and port (e.g. `1.2.3.4:51820`)
3. **Tap Connect**
4. **Open the WireGuard app** (from the App Store) and configure a tunnel:
   - Set **Endpoint** to `127.0.0.1:9000`
   - Set **AllowedIPs** to `0.0.0.0/1, 128.0.0.0/1` (to avoid routing loops)
5. **Activate** the WireGuard tunnel

Traffic now flows: WireGuard → local proxy → VK TURN → your WireGuard server.

## Building

### GitHub CI (Recommended)

Push code to GitHub — the **Build IPA** workflow runs automatically.

```bash
# Create a release
git tag v1.1.0
git push --tags
```

Download the IPA from the **Actions** tab → workflow artifacts.

### Local Build

Requires macOS with Xcode.app, Go 1.25+, and XcodeGen.

```bash
./build.sh
# Output: build/VKTurnProxy.ipa
```

## Installing

Sideload the IPA using AltStore or Sideloadly:

1. Connect iPhone to Mac via USB
2. Open AltStore → My Apps → tap "+"
3. Select `VKTurnProxy.ipa`

**Note:** Free Apple ID requires re-signing every 7 days.

## Limitations

- **Foreground only** — proxy stops when the app is killed
- **7-day re-sign** — free Apple ID limitation via AltStore
- **VK API dependent** — VK may change their internal API at any time

## Credits

Based on [vk-turn-proxy](https://github.com/cacggghp/vk-turn-proxy) by cacggghp.
