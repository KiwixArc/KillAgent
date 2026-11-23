# KILLAgent: Architectural Specification & Implementation Directive for Local Desktop Agent

## 1. Executive Summary & Purpose

`KILLAgent` is a lightweight, zero-footprint desktop background daemon built in **Java 21 LTS** for Windows workstations. It serves as the physical hardware anchor for the **Ch'aska** Zero Trust Document Management & Digital Signature Platform.

Its primary mission is to mediate cryptographic operations between the web frontend (React SPA) and physical cryptographic smart cards (**Peruvian Electronic Identity Card - DNIe 3.0 / PKCS#11**) via a secure, local-only WebSocket loopback server.

### Key Architectural Invariants
* **Strict Per-Device Isolation:** Listens **only** on loopback (`127.0.0.1`). It must **never** bind to `0.0.0.0` or expose any socket to the local network (LAN).
* **PIN Isolation (Zero Network Traversal):** The user's DNIe PIN **never** leaves the desktop process. It is never transmitted to the browser, WebSocket, or Ch'aska backend.
* **Anti-Keylogger Input Defense:** PIN entry is protected by an on-screen scrambled virtual keypad with memory wiping.
* **Instant Session Invalidation (Kill-Switch):** Physical card removal triggers immediate cryptographic session termination across the agent and web application.
* **Signed Updates & Integrity Verification:** Update manifests (`update-manifest.json`) and artifacts enforce HTTPS-only retrieval from allowed hosts, SHA-256 checksum validation, and optional Ed25519 manifest signature pinning.

---

## 2. Technology Stack & Runtime Decisions

* **Language & Runtime:** Java 21 LTS.
* **Smart Card & Hardware Subsystem:**
  * Native Windows `WinSCard` via JNA (`SCardGetStatusChange`) with `javax.smartcardio` fallback.
  * `jdk.crypto.cryptoki` (`SunPKCS11`) for RENIEC / IDEMIA / Bit4id PKCS#11 middleware.
* **Local WebSocket Server:** `org.java-websocket:Java-WebSocket` bound strictly to loopback.
* **JSON Serialization:** `com.fasterxml.jackson.core:jackson-databind`.
* **Desktop UI & System Tray:** `Swing` with `com.formdev:flatlaf` (Windows 11 Dark/Light theme sync) and `java.awt.SystemTray`.
* **Environment Configuration:** `dotenv-java` (`System Env -> .env -> %LOCALAPPDATA%\Chaska\KILLAgent\.env -> /config.properties`).
* **Packaging & Distribution:** `jlink` + `jpackage` generating per-user `.msi` installers and portable Windows `.zip` bundles with an embedded stripped Java 21 JRE.
* **Auto-Update Subsystem:** Standard `java.net.http.HttpClient` + `UpdateVerifier` (HTTPS + SHA-256 + Ed25519) + detached PowerShell MSI/portable upgrade runner.

---

## 3. Environment Configuration (`.env` / `config.properties`)

```ini
ENVIRONMENT=production
KILLAGENT_PORT=3000
KILLAGENT_HOST=127.0.0.1
KILLAGENT_SECURE_WSS=false
KILLAGENT_KEYSTORE_PASSWORD=changeit

ALLOWED_ORIGINS=https://chaska.ong.pe,https://*.chaska.ong.pe,https://*.chaska.ngo,https://app.chaska.internal,https://*.workers.dev,https://*.pages.dev,http://localhost:5173,http://127.0.0.1:5173

RENIEC_PKCS11_DLL_PATH_DNI2=C:\\Windows\\System32\\bit4ipki.dll
RENIEC_PKCS11_DLL_PATH_DNI3=C:\\Program Files\\IDEMIA\\IDPlugClassic\\DLLs\\idplug-pkcs11.dll

UI_THEME=auto
SHOW_BALLOON_NOTIFICATIONS=true

UPDATE_ENABLED=true
UPDATE_AUTO_CHECK_ENABLED=true
UPDATE_CHANNEL=stable
UPDATE_MANIFEST_URL=https://github.com/KiwixArc/KillAgent/releases/latest/download/update-manifest.json
UPDATE_CHECK_INTERVAL_HOURS=6
UPDATE_SIGNING_PUBLIC_KEY=
UPDATE_ALLOWED_HOSTS=github.com,objects.githubusercontent.com,release-assets.githubusercontent.com,api.github.com
```

---

## 4. Visual Taskbar & System Tray Integration

### Dynamic System Tray Icons
1. **Gray / Red Dot:** Daemon running, no smart card reader detected.
2. **Orange / Alert:** Reader connected, no DNIe card inserted.
3. **Green / Shield:** DNIe inserted and ready.
4. **Blue / Pulsing:** Cryptographic operation / PIN prompt in progress.

### Taskbar Context Menu Actions
* **Status Pill:** Connection state, reader model, masked DNI, and installed version.
* **Abrir Panel de Diagnóstico:** PC/SC reader info, ATR, PKCS#11 drivers, auto-start status, update state, and AppData shortcut.
* **Buscar Actualizaciones...:** Checks `update-manifest.json`, validates signature/SHA-256, and opens the update installer dialog.
* **Iniciar automáticamente con Windows:** Registers/unregisters `HKCU\...\Run\KILLAgent`.
* **Reiniciar Conexión WebSocket** and **Salir**.

---

## 5. Anti-Keylogger Security & Virtual Keypad Specification

* Randomized numeric keypad per prompt (`SecureRandom`), zero-string `char[]` buffer wiped in place via `Arrays.fill(pinBuffer, '\0')`.
* Optional mouse-only physical keyboard lockout.
* Windows anti-capture protection via `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE / WDA_MONITOR)`.
* Immediate Kill-Switch dismissal on physical card removal (`CARD_REMOVED`).

---

## 6. Communication Protocol & WebSocket Specifications

* Endpoint: `wss://127.0.0.1:3000` or `ws://127.0.0.1:3000`
* `CONNECTION_ESTABLISHED`, `CARD_REMOVED`, `CARD_INSERTED`, `READER_STATUS_CHANGED`, `SIGN_AUTH_CHALLENGE`, `SIGN_DOCUMENT_DIGEST`, `CANCEL_ACTIVE_OPERATION`, `GET_HARDWARE_STATUS`, and structured `ERROR` responses.
* Default Auth prompt description: *"Autenticación Institucional Ch'aska (Verificación DNIe)"*.
