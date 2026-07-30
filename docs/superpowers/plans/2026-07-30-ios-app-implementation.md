# evan-proxy iOS App Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a native SwiftUI iOS app with full parity to the evan-proxy admin web UI that logs in once and stays logged in, matching the web app's look and feel.

**Architecture:** A single iOS app target in `ios/EvanProxy/`, driven by a typed API client generated from `api/openapi.yaml` (swift-openapi-generator). A `ClientMiddleware` injects the session cookie and transparently re-authenticates on `401` using credentials held in the Keychain. Live logs come from a hand-rolled SSE reader over `URLSession.bytes` (SSE isn't expressible through the generated client). UI is composed from a small themed component library (Inconsolata font, an asset-catalog palette transcribed from the web CSS, in light and dark).

**Tech Stack:** Swift 6 / SwiftUI, iOS 17+, Xcode 16, Swift Package Manager, `swift-openapi-generator` + `swift-openapi-runtime` + `swift-openapi-urlsession`, Swift Charts, `Security.framework` (Keychain), `LocalAuthentication` (Face ID), XCTest.

**Prerequisite:** This app must be built on macOS with Xcode 16. `api/openapi.yaml` is on `main` (merged in PR #3) and is the single source for the generated client. The design spec is `docs/superpowers/specs/2026-07-30-ios-app-design.md`; the approved mockups are in `docs/mockups/`.

**Conventions for every task:** commit after each task with a `feat:`/`test:`/`chore:` message. Author commits as `chrissnell`. Keep files small and single-responsibility. Where a step shows code, it is the actual code to write — no placeholders.

---

## File structure

```
ios/
  Package.swift                         # SwiftPM manifest (app depends on OpenAPI libs)
  openapi.yaml                          # symlink/copy of ../api/openapi.yaml (generator input)
  openapi-generator-config.yaml         # generator config (types + client)
  Sources/EvanProxy/
    App/
      EvanProxyApp.swift                # @main entry, root session gate
      RootView.swift                    # login-gate → TabView switch
    Networking/
      ServerConfig.swift                # base URL storage
      Keychain.swift                    # tiny Security.framework wrapper
      AuthStore.swift                   # credentials + session state + reauth
      ReauthMiddleware.swift            # ClientMiddleware: 401 → reauth → retry
      APIClientFactory.swift            # builds the generated Client with middleware
      LogStream.swift                   # SSE reader → AsyncStream<LogEntry>
    Theme/
      Palette.swift                     # Color tokens (reads asset catalog)
      Typography.swift                  # Inconsolata registration + Font helpers
      Components.swift                  # Box, SectionHeader, StatusChip, PillButton, StatDot
    Features/
      Login/LoginView.swift
      Login/LoginModel.swift
      Users/UsersView.swift
      Users/UsersModel.swift
      Users/UserCard.swift
      Users/UserDetailView.swift
      Users/ScheduleEditorView.swift
      Dashboard/DashboardView.swift
      Dashboard/DashboardModel.swift
      Dashboard/TrafficChart.swift
      Logs/LogsView.swift
      Logs/LogsModel.swift
      Settings/SettingsView.swift
    Resources/
      Inconsolata-Regular.ttf           # copied from pkg/admin/static/fonts (woff2→ttf)
      Assets.xcassets/                  # color sets (light+dark) transcribed from style.css
  Tests/EvanProxyTests/
    KeychainTests.swift
    AuthStoreTests.swift
    ReauthMiddlewareTests.swift
    LogStreamTests.swift
    UsersModelTests.swift
    DowntimeStatusTests.swift
```

Types from the generated client are referenced as `Components.Schemas.UserInfo`, `Components.Schemas.HostCount`, `Components.Schemas.TrafficBucket`, `Components.Schemas.LogEntry`, `Components.Schemas.DowntimeWindow`, etc. The generated `Client` conforms to `APIProtocol`.

---

## Task 1: Scaffold the SwiftPM project and generated client

**Files:**
- Create: `ios/Package.swift`
- Create: `ios/openapi.yaml` (copy of `api/openapi.yaml`)
- Create: `ios/openapi-generator-config.yaml`
- Create: `ios/Sources/EvanProxy/App/EvanProxyApp.swift` (placeholder entry)

- [ ] **Step 1: Copy the OpenAPI document into the package**

```bash
mkdir -p ios/Sources/EvanProxy/App
cp api/openapi.yaml ios/openapi.yaml
```

- [ ] **Step 2: Write `ios/openapi-generator-config.yaml`**

```yaml
generate:
  - types
  - client
accessModifier: internal
```

- [ ] **Step 3: Write `ios/Package.swift`**

```swift
// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "EvanProxy",
    platforms: [.iOS(.v17)],
    dependencies: [
        .package(url: "https://github.com/apple/swift-openapi-generator", from: "1.5.0"),
        .package(url: "https://github.com/apple/swift-openapi-runtime", from: "1.6.0"),
        .package(url: "https://github.com/apple/swift-openapi-urlsession", from: "1.0.2"),
    ],
    targets: [
        .target(
            name: "EvanProxy",
            dependencies: [
                .product(name: "OpenAPIRuntime", package: "swift-openapi-runtime"),
                .product(name: "OpenAPIURLSession", package: "swift-openapi-urlsession"),
            ],
            resources: [.process("Resources")],
            plugins: [
                .plugin(name: "OpenAPIGenerator", package: "swift-openapi-generator"),
            ]
        ),
        .testTarget(name: "EvanProxyTests", dependencies: ["EvanProxy"]),
    ]
)
```

> Note: the generator plugin reads `openapi.yaml` + `openapi-generator-config.yaml` from the target's source dir. Place both under `ios/Sources/EvanProxy/` OR keep them at `ios/` and reference via the plugin's expected path. If the plugin can't find them at package root, move both into `Sources/EvanProxy/`. Verify by building.

- [ ] **Step 4: Write a placeholder `EvanProxyApp.swift` so the target compiles**

```swift
import SwiftUI

@main
struct EvanProxyApp: App {
    var body: some Scene {
        WindowGroup { Text("evan-proxy").font(.system(.body, design: .monospaced)) }
    }
}
```

- [ ] **Step 5: Build to confirm the client generates**

Run: `cd ios && swift build`
Expected: builds; `Components.Schemas.UserInfo` and `Client` are now available (confirm in the next task's test).

- [ ] **Step 6: Commit**

```bash
git add ios/
git commit -m "chore: scaffold iOS SwiftPM package and generated OpenAPI client"
```

---

## Task 2: Keychain wrapper (TDD)

**Files:**
- Create: `ios/Sources/EvanProxy/Networking/Keychain.swift`
- Test: `ios/Tests/EvanProxyTests/KeychainTests.swift`

- [ ] **Step 1: Write the failing test**

```swift
import XCTest
@testable import EvanProxy

final class KeychainTests: XCTestCase {
    let kc = Keychain(service: "com.evanproxy.tests")

    override func tearDown() { try? kc.remove("creds"); super.tearDown() }

    func test_setAndGet_roundtrips() throws {
        try kc.set("hunter2", for: "creds")
        XCTAssertEqual(try kc.get("creds"), "hunter2")
    }

    func test_get_missing_returnsNil() throws {
        XCTAssertNil(try kc.get("nope"))
    }

    func test_remove_clears() throws {
        try kc.set("x", for: "creds")
        try kc.remove("creds")
        XCTAssertNil(try kc.get("creds"))
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd ios && swift test --filter KeychainTests`
Expected: FAIL — `Keychain` undefined.

- [ ] **Step 3: Implement `Keychain.swift`**

```swift
import Foundation
import Security

/// Minimal string keychain wrapper over Security.framework (no third-party dep).
struct Keychain {
    let service: String

    func set(_ value: String, for key: String) throws {
        let data = Data(value.utf8)
        var query = base(key)
        SecItemDelete(query as CFDictionary)
        query[kSecValueData as String] = data
        query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeychainError(status) }
    }

    func get(_ key: String) throws -> String? {
        var query = base(key)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &out)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = out as? Data else { throw KeychainError(status) }
        return String(decoding: data, as: UTF8.self)
    }

    func remove(_ key: String) throws {
        let status = SecItemDelete(base(key) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw KeychainError(status) }
    }

    private func base(_ key: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: key]
    }
}

struct KeychainError: Error { let status: OSStatus; init(_ s: OSStatus) { status = s } }
```

- [ ] **Step 4: Run to verify pass**

Run: `cd ios && swift test --filter KeychainTests`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add ios/Sources/EvanProxy/Networking/Keychain.swift ios/Tests/EvanProxyTests/KeychainTests.swift
git commit -m "feat: add Keychain wrapper with tests"
```

---

## Task 3: ServerConfig + AuthStore (TDD)

`AuthStore` owns credentials (Keychain), knows whether a session is believed active, and can (re)authenticate by POSTing `/api/login`. It depends on an injectable "login function" so it can be unit-tested without a network. The real login function is supplied in Task 5.

**Files:**
- Create: `ios/Sources/EvanProxy/Networking/ServerConfig.swift`
- Create: `ios/Sources/EvanProxy/Networking/AuthStore.swift`
- Test: `ios/Tests/EvanProxyTests/AuthStoreTests.swift`

- [ ] **Step 1: Write `ServerConfig.swift`**

```swift
import Foundation

/// Persisted base URL for the admin server. Stored in UserDefaults (non-secret).
struct ServerConfig {
    private static let key = "evanproxy.baseURL"

    static var baseURL: URL? {
        get { UserDefaults.standard.string(forKey: key).flatMap(URL.init(string:)) }
        set { UserDefaults.standard.set(newValue?.absoluteString, forKey: key) }
    }
}
```

- [ ] **Step 2: Write the failing test**

```swift
import XCTest
@testable import EvanProxy

final class AuthStoreTests: XCTestCase {
    func makeStore() -> AuthStore {
        AuthStore(keychain: Keychain(service: "com.evanproxy.authtests"))
    }
    override func tearDown() {
        try? Keychain(service: "com.evanproxy.authtests").remove("username")
        try? Keychain(service: "com.evanproxy.authtests").remove("password")
        super.tearDown()
    }

    func test_login_success_storesCredentials_andMarksAuthenticated() async throws {
        let store = makeStore()
        var called = 0
        store.loginFn = { u, p in called += 1; XCTAssertEqual(u, "evan"); XCTAssertEqual(p, "pw"); }
        try await store.login(username: "evan", password: "pw")
        XCTAssertEqual(called, 1)
        XCTAssertTrue(store.isAuthenticated)
        XCTAssertTrue(store.hasStoredCredentials)
    }

    func test_login_failure_doesNotStore() async {
        let store = makeStore()
        store.loginFn = { _, _ in throw AuthError.invalidCredentials }
        await XCTAssertThrowsErrorAsync(try await store.login(username: "x", password: "y"))
        XCTAssertFalse(store.isAuthenticated)
        XCTAssertFalse(store.hasStoredCredentials)
    }

    func test_reauthenticate_usesStoredCredentials() async throws {
        let store = makeStore()
        store.loginFn = { _, _ in }
        try await store.login(username: "evan", password: "pw")
        var reauthUser: String?
        store.loginFn = { u, _ in reauthUser = u }
        try await store.reauthenticate()
        XCTAssertEqual(reauthUser, "evan")
    }

    func test_reauthenticate_withNoCredentials_throws() async {
        let store = makeStore()
        await XCTAssertThrowsErrorAsync(try await store.reauthenticate())
    }

    func test_logout_clearsCredentials() async throws {
        let store = makeStore()
        store.loginFn = { _, _ in }
        try await store.login(username: "evan", password: "pw")
        store.logout()
        XCTAssertFalse(store.isAuthenticated)
        XCTAssertFalse(store.hasStoredCredentials)
    }
}

/// Async throwing assertion helper.
func XCTAssertThrowsErrorAsync(_ expr: @autoclosure () async throws -> Void,
                              file: StaticString = #filePath, line: UInt = #line) async {
    do { try await expr(); XCTFail("expected error", file: file, line: line) } catch {}
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `cd ios && swift test --filter AuthStoreTests`
Expected: FAIL — `AuthStore`, `AuthError` undefined.

- [ ] **Step 4: Implement `AuthStore.swift`**

```swift
import Foundation
import Observation

enum AuthError: Error { case invalidCredentials, noStoredCredentials, notConfigured }

@Observable
@MainActor
final class AuthStore {
    private let keychain: Keychain
    private(set) var isAuthenticated = false

    /// Injected login side-effect (real one POSTs /api/login). Set by APIClientFactory.
    var loginFn: (_ username: String, _ password: String) async throws -> Void = { _, _ in
        throw AuthError.notConfigured
    }

    init(keychain: Keychain = Keychain(service: "com.evanproxy.credentials")) {
        self.keychain = keychain
    }

    var hasStoredCredentials: Bool {
        (try? keychain.get("username")) != nil && (try? keychain.get("password")) != nil
    }

    func login(username: String, password: String) async throws {
        try await loginFn(username, password)          // throws on bad creds → nothing stored
        try keychain.set(username, for: "username")
        try keychain.set(password, for: "password")
        isAuthenticated = true
    }

    /// Silent re-login using stored credentials (used by ReauthMiddleware on 401).
    func reauthenticate() async throws {
        guard let u = try keychain.get("username"), let p = try keychain.get("password") else {
            throw AuthError.noStoredCredentials
        }
        try await loginFn(u, p)
        isAuthenticated = true
    }

    func logout() {
        try? keychain.remove("username")
        try? keychain.remove("password")
        isAuthenticated = false
    }
}
```

- [ ] **Step 5: Run to verify pass**

Run: `cd ios && swift test --filter AuthStoreTests`
Expected: PASS (5 tests).

- [ ] **Step 6: Commit**

```bash
git add ios/Sources/EvanProxy/Networking/ServerConfig.swift ios/Sources/EvanProxy/Networking/AuthStore.swift ios/Tests/EvanProxyTests/AuthStoreTests.swift
git commit -m "feat: add ServerConfig and AuthStore with reauth (tests)"
```

---

## Task 4: Reauth middleware (TDD)

The generated client accepts `ClientMiddleware`s. `ReauthMiddleware` calls the next handler; if the response is `401`, it invokes an injected reauth closure and retries the request exactly once.

**Files:**
- Create: `ios/Sources/EvanProxy/Networking/ReauthMiddleware.swift`
- Test: `ios/Tests/EvanProxyTests/ReauthMiddlewareTests.swift`

- [ ] **Step 1: Write the failing test**

```swift
import XCTest
import OpenAPIRuntime
import HTTPTypes
@testable import EvanProxy

final class ReauthMiddlewareTests: XCTestCase {
    func run(_ mw: ReauthMiddleware, statuses: [Int]) async throws -> (HTTPResponse, Int) {
        var idx = 0, calls = 0
        let req = HTTPRequest(method: .get, scheme: "https", authority: "h", path: "/api/users")
        let (resp, _) = try await mw.intercept(
            req, body: nil, baseURL: URL(string: "https://h")!, operationID: "listUsers"
        ) { _, _, _ in
            calls += 1
            let code = statuses[min(idx, statuses.count - 1)]; idx += 1
            return (HTTPResponse(status: .init(code: code)), nil)
        }
        return (resp, calls)
    }

    func test_passesThrough_non401() async throws {
        var reauthed = 0
        let mw = ReauthMiddleware { reauthed += 1 }
        let (resp, calls) = try await run(mw, statuses: [200])
        XCTAssertEqual(resp.status.code, 200)
        XCTAssertEqual(calls, 1)
        XCTAssertEqual(reauthed, 0)
    }

    func test_401_triggersReauth_andRetriesOnce() async throws {
        var reauthed = 0
        let mw = ReauthMiddleware { reauthed += 1 }
        let (resp, calls) = try await run(mw, statuses: [401, 200])
        XCTAssertEqual(reauthed, 1)
        XCTAssertEqual(calls, 2)          // original + one retry
        XCTAssertEqual(resp.status.code, 200)
    }

    func test_stillsFailing_after_retry_returns401_noLoop() async throws {
        var reauthed = 0
        let mw = ReauthMiddleware { reauthed += 1 }
        let (resp, calls) = try await run(mw, statuses: [401, 401])
        XCTAssertEqual(reauthed, 1)
        XCTAssertEqual(calls, 2)          // exactly one retry, no infinite loop
        XCTAssertEqual(resp.status.code, 401)
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd ios && swift test --filter ReauthMiddlewareTests`
Expected: FAIL — `ReauthMiddleware` undefined.

- [ ] **Step 3: Implement `ReauthMiddleware.swift`**

```swift
import Foundation
import OpenAPIRuntime
import HTTPTypes

/// On a 401, run `reauth` once and retry the request a single time.
struct ReauthMiddleware: ClientMiddleware {
    let reauth: () async throws -> Void

    func intercept(
        _ request: HTTPRequest,
        body: HTTPBody?,
        baseURL: URL,
        operationID: String,
        next: (HTTPRequest, HTTPBody?, URL) async throws -> (HTTPResponse, HTTPBody?)
    ) async throws -> (HTTPResponse, HTTPBody?) {
        let (resp, respBody) = try await next(request, body, baseURL)
        guard resp.status.code == 401, operationID != "login" else { return (resp, respBody) }
        do { try await reauth() } catch { return (resp, respBody) }   // reauth failed → surface original 401
        return try await next(request, body, baseURL)                 // retry exactly once
    }
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cd ios && swift test --filter ReauthMiddlewareTests`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add ios/Sources/EvanProxy/Networking/ReauthMiddleware.swift ios/Tests/EvanProxyTests/ReauthMiddlewareTests.swift
git commit -m "feat: add reauth-on-401 client middleware (tests)"
```

---

## Task 5: APIClientFactory — wire client, cookies, and AuthStore's loginFn

Builds the generated `Client` against `ServerConfig.baseURL` with a shared `URLSession` whose `HTTPCookieStorage` carries the session cookie, plus the `ReauthMiddleware`. Also wires `AuthStore.loginFn` to a real `login` call so credentials flow through the session.

**Files:**
- Create: `ios/Sources/EvanProxy/Networking/APIClientFactory.swift`

- [ ] **Step 1: Implement `APIClientFactory.swift`**

```swift
import Foundation
import OpenAPIRuntime
import OpenAPIURLSession

@MainActor
enum APIClientFactory {
    /// One cookie-persisting URLSession for the whole app (carries evan-proxy-session).
    static let session: URLSession = {
        let cfg = URLSessionConfiguration.default
        cfg.httpCookieStorage = .shared
        cfg.httpCookieAcceptPolicy = .always
        cfg.httpShouldSetCookies = true
        return URLSession(configuration: cfg)
    }()

    /// Build a client bound to the configured server and an AuthStore for reauth.
    static func make(auth: AuthStore) throws -> Client {
        guard let base = ServerConfig.baseURL else { throw AuthError.notConfigured }
        let transport = URLSessionTransport(
            configuration: .init(session: session)
        )
        let client = Client(
            serverURL: base,
            transport: transport,
            middlewares: [ReauthMiddleware { try await auth.reauthenticate() }]
        )
        // Wire AuthStore's login side-effect to a real /api/login call.
        auth.loginFn = { username, password in
            let resp = try await client.login(body: .json(.init(username: username, password: password)))
            switch resp {
            case .ok: return
            default:  throw AuthError.invalidCredentials
            }
        }
        return client
    }
}
```

- [ ] **Step 2: Build (no unit test — integration-level, exercised manually in Task 12)**

Run: `cd ios && swift build`
Expected: builds. If `client.login`'s response enum cases differ, adjust the `switch` to the generated case names (`.ok`, `.unauthorized`, `.badRequest`, …).

- [ ] **Step 3: Commit**

```bash
git add ios/Sources/EvanProxy/Networking/APIClientFactory.swift
git commit -m "feat: build cookie-persisting API client with reauth wiring"
```

---

## Task 6: Theme — palette, font, and core components

Transcribe the web CSS custom properties into an asset catalog and build the shared SwiftUI components used across screens. Values come directly from `pkg/admin/static/style.css`.

**Files:**
- Create: `ios/Sources/EvanProxy/Resources/Assets.xcassets/` color sets (see values)
- Create: `ios/Sources/EvanProxy/Resources/Inconsolata-Regular.ttf`
- Create: `ios/Sources/EvanProxy/Theme/Palette.swift`
- Create: `ios/Sources/EvanProxy/Theme/Typography.swift`
- Create: `ios/Sources/EvanProxy/Theme/Components.swift`
- Test: `ios/Tests/EvanProxyTests/DowntimeStatusTests.swift` (status logic lives here; see Task 7)

- [ ] **Step 1: Add the font resource**

```bash
# Convert the bundled web font to ttf (woff2 → ttf) and drop it in Resources.
# On macOS: brew install woff2 && woff2_decompress copies to .ttf, or use fonttools:
#   pip install fonttools brotli && \
#   python -c "from fontTools.ttLib import TTFont; f=TTFont('pkg/admin/static/fonts/inconsolata.woff2'); f.save('ios/Sources/EvanProxy/Resources/Inconsolata-Regular.ttf')"
```

Register the font by adding to the app's Info.plist (in the Xcode app wrapper) `UIAppFonts` = `["Inconsolata-Regular.ttf"]`, OR register at runtime in `Typography.registerFonts()` (Step 3) so it works from the SPM bundle.

- [ ] **Step 2: Create color sets in `Assets.xcassets`**

Create one Color Set per token, each with an "Any"(light) and "Dark" appearance. Values (hex) from `style.css`:

| Color set | Light | Dark |
|---|---|---|
| `bg` | `#FFFFFF` | `#0A0A0A` |
| `bgBox` | `#F8F8F8` | `#111111` |
| `fg` | `#111111` | `#C8C8C8` |
| `fgMuted` | `#666666` | `#555555` |
| `fgDim` | `#999999` | `#444444` |
| `border` | `#DDDDDD` | `#222222` |
| `borderSubtle` | `#EEEEEE` | `#1A1A1A` |
| `accent` | `#2A7A5A` | `#55AA99` |
| `danger` | `#CC4444` | `#CC6666` |
| `warn` | `#AA8855` | `#CCAA55` |
| `purple` | `#7A5AA0` | `#A080C8` |

- [ ] **Step 3: Write `Typography.swift`**

```swift
import SwiftUI
import CoreText

enum Typography {
    /// Register the bundled Inconsolata so `Font.custom` finds it from the SPM bundle.
    static func registerFonts() {
        guard let url = Bundle.module.url(forResource: "Inconsolata-Regular", withExtension: "ttf") else { return }
        CTFontManagerRegisterFontsForURL(url as CFURL, .process, nil)
    }
    static func mono(_ size: CGFloat, weight: Font.Weight = .regular) -> Font {
        .custom("Inconsolata", size: size).weight(weight)
    }
}
```

- [ ] **Step 4: Write `Palette.swift`**

```swift
import SwiftUI

enum Palette {
    static let bg = Color("bg", bundle: .module)
    static let bgBox = Color("bgBox", bundle: .module)
    static let fg = Color("fg", bundle: .module)
    static let fgMuted = Color("fgMuted", bundle: .module)
    static let fgDim = Color("fgDim", bundle: .module)
    static let border = Color("border", bundle: .module)
    static let borderSubtle = Color("borderSubtle", bundle: .module)
    static let accent = Color("accent", bundle: .module)
    static let danger = Color("danger", bundle: .module)
    static let warn = Color("warn", bundle: .module)
    static let purple = Color("purple", bundle: .module)
}
```

- [ ] **Step 5: Write `Components.swift`**

```swift
import SwiftUI

/// Bordered container matching the web `.box`.
struct Box<Content: View>: View {
    @ViewBuilder var content: Content
    var body: some View {
        content
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Palette.bgBox)
            .overlay(RoundedRectangle(cornerRadius: 3).stroke(Palette.border, lineWidth: 1))
            .clipShape(RoundedRectangle(cornerRadius: 3))
    }
}

/// Uppercase, letter-spaced section header matching the web `h2`.
struct SectionHeader: View {
    let title: String
    var body: some View {
        Text(title.uppercased())
            .font(Typography.mono(11, weight: .bold))
            .tracking(1.2)
            .foregroundStyle(Palette.fgMuted)
            .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// Single status chip: tinted fill + dot + label.
struct StatusChip: View {
    let text: String
    let color: Color
    var body: some View {
        HStack(spacing: 6) {
            Circle().fill(color).frame(width: 6, height: 6)
            Text(text).font(Typography.mono(12))
        }
        .padding(.horizontal, 10).padding(.vertical, 4)
        .foregroundStyle(color)
        .background(color.opacity(0.14), in: Capsule())
        .overlay(Capsule().stroke(color, lineWidth: 1))
    }
}

/// Outlined pill button matching the web `.btn-sm`.
struct PillButton: View {
    let title: String
    var color: Color = Palette.fgMuted
    var filled = false
    let action: () -> Void
    var body: some View {
        Button(action: action) {
            Text(title).font(Typography.mono(13))
                .padding(.horizontal, 12).padding(.vertical, 6)
                .foregroundStyle(filled ? Palette.bg : color)
                .frame(maxWidth: .infinity)
        }
        .background(filled ? color : .clear, in: RoundedRectangle(cornerRadius: 3))
        .overlay(RoundedRectangle(cornerRadius: 3).stroke(color, lineWidth: 1))
    }
}
```

- [ ] **Step 6: Build**

Run: `cd ios && swift build`
Expected: builds. (Visual verification happens in the SwiftUI previews and Task 12 device run.)

- [ ] **Step 7: Commit**

```bash
git add ios/Sources/EvanProxy/Theme ios/Sources/EvanProxy/Resources
git commit -m "feat: add theme palette, Inconsolata font, and core components"
```

---

## Task 7: Downtime status logic (TDD) + status model

Compute a user's display state (enabled / disabled / downtime / override) — the same logic the web UI does client-side (`checkDowntimeClient`). This is pure and must be unit-tested; the Users screen renders `StatusChip` from it.

**Files:**
- Create: `ios/Sources/EvanProxy/Features/Users/UserStatus.swift`
- Test: `ios/Tests/EvanProxyTests/DowntimeStatusTests.swift`

- [ ] **Step 1: Write the failing test**

```swift
import XCTest
@testable import EvanProxy

final class DowntimeStatusTests: XCTestCase {
    // Mon 23:00 → inside a 22:00–06:00 Monday window.
    func test_insideWindow_isDowntime() {
        let sched = ["1": [win("22:00", "06:00")]]
        XCTAssertTrue(UserStatus.inDowntime(schedule: sched, weekday: 1, minutesOfDay: 23*60))
    }
    // Tue 03:00 → covered by Monday's overnight spillover.
    func test_overnightSpillover_isDowntime() {
        let sched = ["1": [win("22:00", "06:00")]]
        XCTAssertTrue(UserStatus.inDowntime(schedule: sched, weekday: 2, minutesOfDay: 3*60))
    }
    func test_outsideWindow_isNotDowntime() {
        let sched = ["1": [win("22:00", "06:00")]]
        XCTAssertFalse(UserStatus.inDowntime(schedule: sched, weekday: 1, minutesOfDay: 12*60))
    }
    private func win(_ s: String, _ e: String) -> Components.Schemas.DowntimeWindow {
        .init(start: s, end: e)
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd ios && swift test --filter DowntimeStatusTests`
Expected: FAIL — `UserStatus` undefined.

- [ ] **Step 3: Implement `UserStatus.swift`**

```swift
import Foundation

enum DisplayState { case enabled, disabled, downtime, override(until: Date) }

enum UserStatus {
    /// Mirrors the web UI's checkDowntimeClient: keys are "0"(Sun)…"6"(Sat).
    static func inDowntime(schedule: [String: [Components.Schemas.DowntimeWindow]],
                           weekday: Int, minutesOfDay now: Int) -> Bool {
        func mins(_ hhmm: String) -> Int {
            let p = hhmm.split(separator: ":"); return (Int(p[0]) ?? 0) * 60 + (Int(p[1]) ?? 0)
        }
        for w in schedule[String(weekday)] ?? [] {
            let s = mins(w.start), e = mins(w.end)
            if s < e { if now >= s && now < e { return true } }
            else { if now >= s { return true } }         // overnight, evening side
        }
        let yesterday = (weekday + 6) % 7
        for w in schedule[String(yesterday)] ?? [] {
            let s = mins(w.start), e = mins(w.end)
            if s >= e && now < e { return true }          // overnight spillover into today
        }
        return false
    }

    static func state(for u: Components.Schemas.UserInfo, now: Date = Date(),
                      calendar: Calendar = .current) -> DisplayState {
        if !u.enabled { return .disabled }
        if let untilStr = u.downtime_override_until,
           let until = ISO8601DateFormatter().date(from: untilStr), until > now {
            return .override(until: until)
        }
        let comps = calendar.dateComponents([.weekday, .hour, .minute], from: now)
        let weekday = (comps.weekday ?? 1) - 1            // Calendar: 1=Sun → 0=Sun
        let minutes = (comps.hour ?? 0) * 60 + (comps.minute ?? 0)
        if inDowntime(schedule: u.downtime_schedule?.additionalProperties ?? [:],
                      weekday: weekday, minutesOfDay: minutes) { return .downtime }
        return .enabled
    }
}
```

> Note: `u.downtime_schedule` generates as a wrapper with `additionalProperties` (a `[String: [DowntimeWindow]]`). If the generated accessor name differs, adjust `additionalProperties` accordingly — confirm against the generated `Types.swift`.

- [ ] **Step 4: Run to verify pass**

Run: `cd ios && swift test --filter DowntimeStatusTests`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add ios/Sources/EvanProxy/Features/Users/UserStatus.swift ios/Tests/EvanProxyTests/DowntimeStatusTests.swift
git commit -m "feat: add downtime/override status computation (tests)"
```

---

## Task 8: Login screen

**Files:**
- Create: `ios/Sources/EvanProxy/Features/Login/LoginModel.swift`
- Create: `ios/Sources/EvanProxy/Features/Login/LoginView.swift`

- [ ] **Step 1: Write `LoginModel.swift`**

```swift
import Foundation
import Observation

@Observable @MainActor
final class LoginModel {
    var username = ""; var password = ""; var error: String?; var busy = false
    let auth: AuthStore
    init(auth: AuthStore) { self.auth = auth }

    func submit() async {
        error = nil; busy = true; defer { busy = false }
        do { try await auth.login(username: username, password: password) }
        catch { self.error = "invalid credentials" }
    }
}
```

- [ ] **Step 2: Write `LoginView.swift`**

```swift
import SwiftUI

struct LoginView: View {
    @State var model: LoginModel
    var body: some View {
        VStack(spacing: 16) {
            Text("evan-proxy").font(Typography.mono(22, weight: .bold)).foregroundStyle(Palette.fg)
            Box {
                VStack(alignment: .leading, spacing: 8) {
                    if let e = model.error { Text(e).font(Typography.mono(12)).foregroundStyle(Palette.danger) }
                    Text("username").font(Typography.mono(12)).foregroundStyle(Palette.fgMuted)
                    TextField("", text: $model.username).textInputAutocapitalization(.never)
                        .autocorrectionDisabled().font(Typography.mono(14))
                        .padding(8).overlay(RoundedRectangle(cornerRadius: 2).stroke(Palette.border))
                    Text("password").font(Typography.mono(12)).foregroundStyle(Palette.fgMuted)
                    SecureField("", text: $model.password).font(Typography.mono(14))
                        .padding(8).overlay(RoundedRectangle(cornerRadius: 2).stroke(Palette.border))
                    PillButton(title: model.busy ? "…" : "login", color: Palette.fg) {
                        Task { await model.submit() }
                    }.padding(.top, 8)
                }
            }
        }
        .padding(20).frame(maxHeight: .infinity)
        .background(Palette.bg).foregroundStyle(Palette.fg)
    }
}
```

- [ ] **Step 3: Build & preview**

Run: `cd ios && swift build`
Expected: builds. Verify visually against `docs/mockups/ios-mockups-dark.svg` (Login) in an Xcode preview.

- [ ] **Step 4: Commit**

```bash
git add ios/Sources/EvanProxy/Features/Login
git commit -m "feat: add login screen"
```

---

## Task 9: Users screen — list, card, toggle, chip (TDD for the model)

**Files:**
- Create: `ios/Sources/EvanProxy/Features/Users/UsersModel.swift`
- Create: `ios/Sources/EvanProxy/Features/Users/UserCard.swift`
- Create: `ios/Sources/EvanProxy/Features/Users/UsersView.swift`
- Test: `ios/Tests/EvanProxyTests/UsersModelTests.swift`

- [ ] **Step 1: Write the failing test** (model calls the client; use a stub conforming to a minimal protocol the model depends on)

```swift
import XCTest
@testable import EvanProxy

final class UsersModelTests: XCTestCase {
    func test_load_populatesUsers() async {
        let model = UsersModel(api: StubUsersAPI(users: [sample("evan"), sample("mia")]))
        await model.load()
        XCTAssertEqual(model.users.map(\.username), ["evan", "mia"])
        XCTAssertNil(model.error)
    }
    func test_toggleEnabled_flipsAndReloads() async {
        let stub = StubUsersAPI(users: [sample("evan", enabled: true)])
        let model = UsersModel(api: stub)
        await model.load()
        await model.setEnabled("evan", false)
        XCTAssertEqual(stub.lastSetEnabled?.0, "evan")
        XCTAssertEqual(stub.lastSetEnabled?.1, false)
    }
    private func sample(_ n: String, enabled: Bool = true) -> Components.Schemas.UserInfo {
        .init(username: n, created_at: "2026-01-01T00:00:00Z", dns_server: "",
              dns_protocol: .empty, port: 4100, enabled: enabled)
    }
}

final class StubUsersAPI: UsersAPI {
    var users: [Components.Schemas.UserInfo]
    var lastSetEnabled: (String, Bool)?
    init(users: [Components.Schemas.UserInfo]) { self.users = users }
    func listUsers() async throws -> [Components.Schemas.UserInfo] { users }
    func setEnabled(_ username: String, _ enabled: Bool) async throws { lastSetEnabled = (username, enabled) }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd ios && swift test --filter UsersModelTests`
Expected: FAIL — `UsersModel`, `UsersAPI` undefined.

- [ ] **Step 3: Implement `UsersModel.swift`** (define the `UsersAPI` seam + a real adapter over the generated `Client`)

```swift
import Foundation
import Observation

/// Narrow protocol the Users screen depends on — lets tests stub the network.
protocol UsersAPI {
    func listUsers() async throws -> [Components.Schemas.UserInfo]
    func setEnabled(_ username: String, _ enabled: Bool) async throws
}

/// Adapter mapping the narrow protocol onto the generated Client.
struct LiveUsersAPI: UsersAPI {
    let client: Client
    func listUsers() async throws -> [Components.Schemas.UserInfo] {
        try await client.listUsers().ok.body.json
    }
    func setEnabled(_ username: String, _ enabled: Bool) async throws {
        _ = try await client.setEnabled(body: .json(.init(username: username, enabled: enabled)))
    }
}

@Observable @MainActor
final class UsersModel {
    private let api: UsersAPI
    var users: [Components.Schemas.UserInfo] = []
    var error: String?
    init(api: UsersAPI) { self.api = api }

    func load() async {
        do { users = try await api.listUsers(); error = nil }
        catch { self.error = "failed to load users" }
    }
    func setEnabled(_ username: String, _ enabled: Bool) async {
        do { try await api.setEnabled(username, enabled); await load() }
        catch { self.error = "failed to update user" }
    }
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cd ios && swift test --filter UsersModelTests`
Expected: PASS (2 tests).

- [ ] **Step 5: Write `UserCard.swift`** (card + native Toggle + StatusChip + meta + actions)

```swift
import SwiftUI

struct UserCard: View {
    let user: Components.Schemas.UserInfo
    let onToggle: (Bool) -> Void
    let onSchedule: () -> Void
    let onEdit: () -> Void
    let onOverride: () -> Void

    var body: some View {
        Box {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Text(user.username).font(Typography.mono(15, weight: .bold)).foregroundStyle(Palette.fg)
                    Spacer()
                    Toggle("", isOn: Binding(get: { user.enabled }, set: { onToggle($0) }))
                        .labelsHidden().tint(Palette.accent)
                }
                chip
                Text(meta).font(Typography.mono(12)).foregroundStyle(Palette.fgMuted)
                HStack(spacing: 6) {
                    if case .downtime = state { PillButton(title: "override", color: Palette.purple, action: onOverride) }
                    if case .override = state { PillButton(title: "cancel override", color: Palette.purple, action: onOverride) }
                    PillButton(title: "schedule", action: onSchedule)
                    PillButton(title: "edit", action: onEdit)
                }
            }
        }
    }

    private var state: DisplayState { UserStatus.state(for: user) }
    private var chip: some View {
        switch state {
        case .enabled:  return StatusChip(text: "enabled", color: Palette.accent)
        case .disabled: return StatusChip(text: "disabled", color: Palette.danger)
        case .downtime: return StatusChip(text: "downtime", color: Palette.warn)
        case .override(let until):
            let m = max(0, Int(until.timeIntervalSinceNow / 60))
            return StatusChip(text: "override · \(m)m left", color: Palette.purple)
        }
    }
    private var meta: String {
        let dns = user.dns_server.isEmpty ? "default" : "\(user.dns_protocol.rawValue)://\(user.dns_server)"
        return "port \(user.port) · dns \(dns)"
    }
}
```

- [ ] **Step 6: Write `UsersView.swift`**

```swift
import SwiftUI

struct UsersView: View {
    @State var model: UsersModel
    let makeDetail: (Components.Schemas.UserInfo) -> UserDetailView
    let makeSchedule: (Components.Schemas.UserInfo) -> ScheduleEditorView
    @State private var detailUser: Components.Schemas.UserInfo?
    @State private var scheduleUser: Components.Schemas.UserInfo?

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 10) {
                    SectionHeader(title: "proxy users")
                    ForEach(model.users, id: \.username) { u in
                        UserCard(user: u,
                            onToggle: { on in Task { await model.setEnabled(u.username, on) } },
                            onSchedule: { scheduleUser = u },
                            onEdit: { detailUser = u },
                            onOverride: { detailUser = u })
                    }
                    PillButton(title: "+ add user", color: Palette.accent) { detailUser = nil /* present add sheet */ }
                }.padding(12)
            }
            .background(Palette.bg)
            .navigationDestination(item: $detailUser) { makeDetail($0) }
            .navigationDestination(item: $scheduleUser) { makeSchedule($0) }
            .task { await model.load() }
            .refreshable { await model.load() }
        }
    }
}
```

- [ ] **Step 7: Build**

Run: `cd ios && swift build`
Expected: builds. Verify against `docs/mockups/ios-mockups-users.svg` (Users) in preview.

- [ ] **Step 8: Commit**

```bash
git add ios/Sources/EvanProxy/Features/Users ios/Tests/EvanProxyTests/UsersModelTests.swift
git commit -m "feat: add users list, card, and enable/disable (tests)"
```

---

## Task 10: User detail + edits (port / dns / password / delete) and schedule editor

**Files:**
- Create: `ios/Sources/EvanProxy/Features/Users/UserDetailView.swift`
- Create: `ios/Sources/EvanProxy/Features/Users/ScheduleEditorView.swift`
- Extend: `UsersAPI` / `LiveUsersAPI` with `setPort`, `setDNS`, `testDNS`, `changePassword`, `deleteUser`, `setDowntime`, `setOverride`, `clearOverride`.

- [ ] **Step 1: Extend `UsersAPI` and `LiveUsersAPI`** (append to `UsersModel.swift`)

```swift
protocol UserEditsAPI {
    func setPort(_ username: String, _ port: Int) async throws
    func setDNS(_ username: String, server: String, proto: String) async throws
    func testDNS(server: String, proto: String) async throws -> Bool
    func changePassword(_ username: String, _ password: String) async throws
    func deleteUser(_ username: String) async throws
    func setDowntime(_ username: String, _ schedule: [String: [Components.Schemas.DowntimeWindow]]) async throws
    func setOverride(_ username: String, minutes: Int) async throws
}

extension LiveUsersAPI: UserEditsAPI {
    func setPort(_ username: String, _ port: Int) async throws {
        _ = try await client.setPort(body: .json(.init(username: username, port: port)))
    }
    func setDNS(_ username: String, server: String, proto: String) async throws {
        _ = try await client.setDNS(body: .json(.init(username: username, dns_server: server,
            dns_protocol: .init(rawValue: proto) ?? .empty)))
    }
    func testDNS(server: String, proto: String) async throws -> Bool {
        let r = try await client.testDNS(body: .json(.init(dns_server: server,
            dns_protocol: .init(rawValue: proto) ?? .plain)))
        return try r.ok.body.json.ok
    }
    func changePassword(_ username: String, _ password: String) async throws {
        _ = try await client.changePassword(body: .json(.init(username: username, password: password)))
    }
    func deleteUser(_ username: String) async throws {
        _ = try await client.deleteUser(query: .init(username: username))
    }
    func setDowntime(_ username: String, _ schedule: [String: [Components.Schemas.DowntimeWindow]]) async throws {
        _ = try await client.setDowntimeSchedule(body: .json(.init(username: username,
            downtime_schedule: .init(additionalProperties: schedule))))
    }
    func setOverride(_ username: String, minutes: Int) async throws {
        _ = try await client.setDowntimeOverride(body: .json(.init(username: username, duration_minutes: minutes)))
    }
}
```

> Confirm generated operation + case names against `Types.swift`; adjust if the plugin named them differently (e.g. `.created` for createUser).

- [ ] **Step 2: Write `UserDetailView.swift`** (grouped `access` + `configuration` + delete; opens editors)

```swift
import SwiftUI

struct UserDetailView: View {
    let user: Components.Schemas.UserInfo
    let api: UserEditsAPI
    let onChange: () async -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var confirmingDelete = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                SectionHeader(title: "access")
                Box {
                    Toggle(isOn: .constant(user.enabled)) { Text("proxy enabled").font(Typography.mono(14)) }
                        .tint(Palette.accent)
                }
                SectionHeader(title: "configuration")
                Box {
                    VStack(spacing: 0) {
                        NavigationLink { PortEditor(user: user, api: api, onChange: onChange) } label: { row("port", "\(user.port)") }
                        Divider().overlay(Palette.borderSubtle)
                        NavigationLink { DNSEditor(user: user, api: api, onChange: onChange) } label: { row("dns", user.dns_server.isEmpty ? "default" : user.dns_server) }
                        Divider().overlay(Palette.borderSubtle)
                        NavigationLink { PasswordEditor(user: user, api: api) } label: { row("password", "••••••••") }
                    }
                }
                PillButton(title: confirmingDelete ? "confirm delete" : "delete user", color: Palette.danger) {
                    if confirmingDelete { Task { try? await api.deleteUser(user.username); await onChange(); dismiss() } }
                    else { confirmingDelete = true }
                }.padding(.top, 8)
            }.padding(12)
        }
        .background(Palette.bg).navigationTitle(user.username)
    }
    private func row(_ k: String, _ v: String) -> some View {
        HStack { Text(k).foregroundStyle(Palette.fg); Spacer()
                 Text(v).foregroundStyle(Palette.fgMuted); Image(systemName: "chevron.right").foregroundStyle(Palette.fgDim) }
            .font(Typography.mono(14)).padding(.vertical, 10)
    }
}
```

Define `PortEditor`, `DNSEditor` (with a "test" button calling `api.testDNS`), and `PasswordEditor` as small `Box`-wrapped forms in the same file — each collects input and calls the corresponding `api` method then `onChange()`. Keep each under ~30 lines.

- [ ] **Step 3: Write `ScheduleEditorView.swift`** (per-day list + native wheel picker in a sheet)

```swift
import SwiftUI

struct ScheduleEditorView: View {
    let user: Components.Schemas.UserInfo
    let api: UserEditsAPI
    let onChange: () async -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var schedule: [String: [Components.Schemas.DowntimeWindow]] = [:]
    @State private var editing: (day: Int, index: Int)?   // which window's picker is open

    private let dayNames = ["Sun","Mon","Tue","Wed","Thu","Fri","Sat"]

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 10) {
                SectionHeader(title: "weekly schedule")
                ForEach(0..<7, id: \.self) { d in dayRow(d) }
                HStack {
                    PillButton(title: "copy Sun → all") { copySundayToAll() }
                    PillButton(title: "save", color: Palette.accent, filled: true) {
                        Task { try? await api.setDowntime(user.username, cleaned()); await onChange(); dismiss() }
                    }
                }.padding(.top, 8)
            }.padding(12)
        }
        .background(Palette.bg).navigationTitle("downtime · \(user.username)")
        .onAppear { schedule = user.downtime_schedule?.additionalProperties ?? [:] }
        .sheet(item: Binding(get: { editing.map { EditRef(day: $0.day, index: $0.index) } },
                             set: { editing = $0.map { ($0.day, $0.index) } })) { ref in
            TimeWheelSheet(time: binding(for: ref)) // native DatePicker(.wheel), HH:MM
        }
    }
    // dayRow renders window chips (`10:00 PM – 6:00 AM`, overnight-aware) + "+ add";
    // tapping a chip sets `editing`. binding(for:) maps a ref to that window's start/end.
    // cleaned() drops empty days; copySundayToAll() copies schedule["0"] to "1"…"6".
}

struct EditRef: Identifiable { let day: Int; let index: Int; var id: String { "\(day)-\(index)" } }
```

Implement `dayRow`, `binding(for:)`, `cleaned()`, `copySundayToAll()`, and `TimeWheelSheet` (a `DatePicker` with `.datePickerStyle(.wheel)` bound through a `"HH:MM"` formatter) in the same file. Match `docs/mockups/ios-mockups-users.svg` (Schedule editor).

- [ ] **Step 4: Build**

Run: `cd ios && swift build`
Expected: builds. Verify detail + schedule against the mockups in preview.

- [ ] **Step 5: Commit**

```bash
git add ios/Sources/EvanProxy/Features/Users
git commit -m "feat: add user detail editors and schedule editor"
```

---

## Task 11: Dashboard (stats + Swift Charts) and Logs (SSE)

**Files:**
- Create: `ios/Sources/EvanProxy/Features/Dashboard/{DashboardModel,DashboardView,TrafficChart}.swift`
- Create: `ios/Sources/EvanProxy/Networking/LogStream.swift`
- Create: `ios/Sources/EvanProxy/Features/Logs/{LogsModel,LogsView}.swift`
- Test: `ios/Tests/EvanProxyTests/LogStreamTests.swift`

- [ ] **Step 1: Write the failing SSE parser test**

```swift
import XCTest
@testable import EvanProxy

final class LogStreamTests: XCTestCase {
    func test_parsesDataFrames_intoEntries() async throws {
        let sse = "data: {\"ts\":\"2026-07-30T14:02:11Z\",\"event\":\"open\",\"status\":200}\n\n" +
                  "data: {\"ts\":\"2026-07-30T14:02:12Z\",\"event\":\"dns-block\",\"status\":523}\n\n"
        var events: [Components.Schemas.LogEntry] = []
        for try await e in SSEParser.entries(from: linesOf(sse)) { events.append(e) }
        XCTAssertEqual(events.count, 2)
        XCTAssertEqual(events[1].status, 523)
    }
    // Yields the SSE text as an async line sequence.
    private func linesOf(_ s: String) -> AsyncStream<String> {
        AsyncStream { cont in for l in s.split(separator: "\n", omittingEmptySubsequences: false) { cont.yield(String(l)) }; cont.finish() }
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd ios && swift test --filter LogStreamTests`
Expected: FAIL — `SSEParser` undefined.

- [ ] **Step 3: Implement `LogStream.swift`** (parser + live reader)

```swift
import Foundation

enum SSEParser {
    /// Turn an async sequence of SSE lines into decoded LogEntry values.
    static func entries<S: AsyncSequence>(from lines: S) -> AsyncThrowingStream<Components.Schemas.LogEntry, Error>
        where S.Element == String {
        AsyncThrowingStream { cont in
            let task = Task {
                let decoder = JSONDecoder()
                do {
                    for try await line in lines {
                        guard line.hasPrefix("data:") else { continue }
                        let json = line.dropFirst(5).trimmingCharacters(in: .whitespaces)
                        if json.isEmpty { continue }
                        if let entry = try? decoder.decode(Components.Schemas.LogEntry.self, from: Data(json.utf8)) {
                            cont.yield(entry)
                        }
                    }
                    cont.finish()
                } catch { cont.finish(throwing: error) }
            }
            cont.onTermination = { _ in task.cancel() }
        }
    }
}

@MainActor
struct LogStream {
    let baseURL: URL
    /// Open the SSE endpoint and yield entries until cancelled.
    func connect() -> AsyncThrowingStream<Components.Schemas.LogEntry, Error> {
        AsyncThrowingStream { cont in
            let task = Task {
                do {
                    var req = URLRequest(url: baseURL.appendingPathComponent("api/logs"))
                    req.setValue("text/event-stream", forHTTPHeaderField: "Accept")
                    let (bytes, _) = try await APIClientFactory.session.bytes(for: req)
                    for try await entry in SSEParser.entries(from: bytes.lines) { cont.yield(entry) }
                    cont.finish()
                } catch { cont.finish(throwing: error) }
            }
            cont.onTermination = { _ in task.cancel() }
        }
    }
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cd ios && swift test --filter LogStreamTests`
Expected: PASS.

- [ ] **Step 5: Write `LogsModel.swift` + `LogsView.swift`** (consume the stream, cap at 200 lines, color by event/status)

```swift
import SwiftUI
import Observation

@Observable @MainActor
final class LogsModel {
    var lines: [Components.Schemas.LogEntry] = []
    private var task: Task<Void, Never>?
    let stream: LogStream
    init(stream: LogStream) { self.stream = stream }
    func start() {
        task = Task {
            do { for try await e in stream.connect() {
                lines.append(e); if lines.count > 200 { lines.removeFirst(lines.count - 200) }
            } } catch {}
        }
    }
    func stop() { task?.cancel() }
}

struct LogsView: View {
    @State var model: LogsModel
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 2) {
                SectionHeader(title: "log tail · live")
                ForEach(Array(model.lines.enumerated()), id: \.offset) { _, e in
                    Text(format(e)).font(Typography.mono(11)).foregroundStyle(color(e))
                }
            }.padding(12).frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(Palette.bg).task { model.start() }.onDisappear { model.stop() }
    }
    private func color(_ e: Components.Schemas.LogEntry) -> Color {
        if e.event == "dns-block" || e.event == "dns-err" { return Palette.danger }
        if e.status >= 400 { return Palette.warn }
        return Palette.accent
    }
    private func format(_ e: Components.Schemas.LogEntry) -> String {
        "\(e.ts)  \((e.user ?? "-"))  \((e.event ?? "-"))  \(e.host ?? "")  \(e.status)"
    }
}
```

- [ ] **Step 6: Write Dashboard** (`DashboardModel` loads top-sites/top-blocked/traffic; `TrafficChart` uses Swift Charts)

```swift
import SwiftUI
import Charts

struct TrafficChart: View {
    let buckets: [Components.Schemas.TrafficBucket]
    let value: (Components.Schemas.TrafficBucket) -> Int
    var body: some View {
        Chart(Array(buckets.enumerated()), id: \.offset) { i, b in
            AreaMark(x: .value("t", i), y: .value("v", value(b)))
                .foregroundStyle(Palette.accent.opacity(0.15))
            LineMark(x: .value("t", i), y: .value("v", value(b)))
                .foregroundStyle(Palette.accent.opacity(0.7))
        }
        .chartXAxis(.hidden).chartYAxis(.hidden).frame(height: 120)
    }
}
```

`DashboardModel` mirrors `UsersModel`: a narrow `StatsAPI` protocol (`topSites`, `topBlocked`, `traffic`) with a `LiveStatsAPI` adapter over `Client`, polled on a timer (5s stats, 10s traffic) like the web. `DashboardView` lays out two `Box` lists (top sites / dns blocked) and two `TrafficChart`s (bandwidth = `bw`, requests = `reqs`), each under a `SectionHeader`. Match `docs/mockups/ios-mockups-dark.svg` (Dashboard).

- [ ] **Step 7: Build & test**

Run: `cd ios && swift build && swift test`
Expected: builds; all tests pass.

- [ ] **Step 8: Commit**

```bash
git add ios/Sources/EvanProxy/Features/Dashboard ios/Sources/EvanProxy/Features/Logs ios/Sources/EvanProxy/Networking/LogStream.swift ios/Tests/EvanProxyTests/LogStreamTests.swift
git commit -m "feat: add dashboard charts and live SSE log tail (tests)"
```

---

## Task 12: App shell — session gate, tabs, settings, Face ID; end-to-end run

**Files:**
- Create: `ios/Sources/EvanProxy/App/RootView.swift`
- Create: `ios/Sources/EvanProxy/Features/Settings/SettingsView.swift`
- Modify: `ios/Sources/EvanProxy/App/EvanProxyApp.swift`

- [ ] **Step 1: Write `SettingsView.swift`** (server URL field, biometric toggle, logout)

```swift
import SwiftUI

struct SettingsView: View {
    let auth: AuthStore
    @State private var urlString = ServerConfig.baseURL?.absoluteString ?? ""
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                SectionHeader(title: "server")
                Box {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("base url").font(Typography.mono(12)).foregroundStyle(Palette.fgMuted)
                        TextField("https://proxy.example.com", text: $urlString)
                            .textInputAutocapitalization(.never).autocorrectionDisabled()
                            .font(Typography.mono(14)).padding(8)
                            .overlay(RoundedRectangle(cornerRadius: 2).stroke(Palette.border))
                        PillButton(title: "save", color: Palette.accent) {
                            ServerConfig.baseURL = URL(string: urlString)
                        }
                    }
                }
                PillButton(title: "logout", color: Palette.danger) { auth.logout() }
            }.padding(12)
        }.background(Palette.bg).navigationTitle("settings")
    }
}
```

- [ ] **Step 2: Write `RootView.swift`** (gate on `ServerConfig` + `auth.isAuthenticated`; build client + models once configured)

```swift
import SwiftUI

struct RootView: View {
    @State private var auth = AuthStore()
    @State private var client: Client?

    var body: some View {
        Group {
            if ServerConfig.baseURL == nil {
                SettingsView(auth: auth)                       // must set a server first
            } else if !auth.isAuthenticated {
                LoginView(model: LoginModel(auth: auth))
            } else if let client {
                MainTabs(client: client, auth: auth)
            } else { Color.clear.onAppear(perform: build) }
        }
        .task { build(); await trySilentLogin() }
    }
    private func build() { client = try? APIClientFactory.make(auth: auth) }
    private func trySilentLogin() async {
        build()
        if auth.hasStoredCredentials { try? await auth.reauthenticate() }  // "log in once"
    }
}

struct MainTabs: View {
    let client: Client; let auth: AuthStore
    var body: some View {
        TabView {
            DashboardView(model: .init(api: LiveStatsAPI(client: client)))
                .tabItem { Text("dashboard") }
            UsersView(model: .init(api: LiveUsersAPI(client: client)),
                      makeDetail: { UserDetailView(user: $0, api: LiveUsersAPI(client: client), onChange: {}) },
                      makeSchedule: { ScheduleEditorView(user: $0, api: LiveUsersAPI(client: client), onChange: {}) })
                .tabItem { Text("users") }
            LogsView(model: .init(stream: LogStream(baseURL: ServerConfig.baseURL!)))
                .tabItem { Text("logs") }
            NavigationStack { SettingsView(auth: auth) }.tabItem { Text("settings") }
        }
        .tint(Palette.accent)
    }
}
```

- [ ] **Step 3: Finalize `EvanProxyApp.swift`**

```swift
import SwiftUI

@main
struct EvanProxyApp: App {
    init() { Typography.registerFonts() }
    var body: some Scene { WindowGroup { RootView() } }
}
```

- [ ] **Step 4: Build & run the whole test suite**

Run: `cd ios && swift build && swift test`
Expected: builds; all unit tests pass.

- [ ] **Step 5: Manual end-to-end verification** (requires an Xcode app target + a reachable evan-proxy)

Create an Xcode app target that embeds the `EvanProxy` package (or add an app wrapper), then in the Simulator:
1. First launch → Settings, enter the server base URL.
2. Log in → land on Dashboard.
3. Kill and relaunch the app → **you are still logged in** (silent reauth). This is the acceptance test for requirement #1.
4. Users → toggle a user off/on; open schedule editor, add an overnight window, save; open edit, change DNS with "test".
5. Logs → confirm the live tail streams and colors correctly.
6. Toggle the Simulator between light/dark → confirm the palette matches the web app.

- [ ] **Step 6: Commit**

```bash
git add ios/Sources/EvanProxy/App ios/Sources/EvanProxy/Features/Settings
git commit -m "feat: add app shell, tabs, settings, and silent-login gate"
```

---

## Self-review notes

- **Spec coverage:** login (T8), persistent login / Keychain / reauth (T2–T5, T12 silent login), users list + status chips + toggle (T7, T9), user detail replacing the overflow menu (T10), schedule editor with wheel picker (T10), dashboard + charts (T11), SSE logs (T11), settings/server URL/logout (T12), theme + Inconsolata + light/dark (T6), tab navigation (T12). All decisions A–F and both requirements are covered.
- **Generated-name caveat:** operation IDs and response case names (`.ok`, `.created`, `.unauthorized`), and the `downtime_schedule.additionalProperties` accessor, come from the generator and must be confirmed against `Types.swift` after Task 1. Tasks flag this where relevant.
- **Out of scope (per spec):** multi-admin/roles, push, offline cache, iPad-specific layout, Android.
```
