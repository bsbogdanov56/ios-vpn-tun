=== Task 10: README Verification ===

1. Prerequisites section:
## Prerequisites

2. Build script mentioned:
   ./build.sh

3. Localhost endpoint documented:
   - Set the **Endpoint** to `127.0.0.1:9000`.

4. AllowedIPs configuration:
   - **CRITICAL:** Update **AllowedIPs** to exclude localhost traffic to prevent loops:
     AllowedIPs = 0.0.0.0/1, 128.0.0.0/1

5. AltStore/Sideloadly installation:
- **AltStore** or **Sideloadly** for installation
Since this app is not on the App Store, you must sideload it using a tool like AltStore or Sideloadly.
1. Install **AltStore** on your Mac.
3. Open AltStore, go to the "My Apps" tab, and tap the "+" icon.
5. **Note:** If you use a free Apple ID, you must re-sign the app every **7 days** through AltStore.

6. 7-day re-signing limitation:
5. **Note:** If you use a free Apple ID, you must re-sign the app every **7 days** through AltStore.
- **Sideloading:** Requires re-signing every 7 days with a free Apple ID.

7. GitHub Actions CI build path:
### Option A: GitHub CI (Recommended)
You can build the IPA without installing any local development tools by using GitHub Actions.
   - Open the official **WireGuard** app (from the App Store).

=== All checks passed ===
