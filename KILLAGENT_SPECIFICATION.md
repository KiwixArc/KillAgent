# KILLAgent: Architectural Specification & Implementation Directive for Local Desktop Agent

## 1. Executive Summary & Purpose

`KILLAgent` is a lightweight, zero-footprint desktop background daemon built in **Java 21 LTS** for Windows workstations. It serves as the physical hardware anchor for the **Ch'asca** Zero Trust Document Management & Digital Signature Platform.

Its primary mission is to mediate cryptographic operations between the web frontend (React SPA) and physical cryptographic smart cards (**Peruvian Electronic Identity Card - DNIe 3.0 / PKCS#11**) via a secure, local-only WebSocket loopback server.

### Key Architectural Invariants
* **Strict Per-Device Isolation:** Listens **only** on loopback (`127.0.0.1`). It must **never** bind to `0.0.0.0` or expose any socket to the local network (LAN).
* **PIN Isolation (Zero Network Traversal):** The user's DNIe PIN **never** leaves the desktop process. It is never transmitted to the browser, WebSocket, or Ch'asca backend.
* **Anti-Keylogger Input Defense:** PIN entry is protected by an on-screen scrambled virtual keypad with memory wiping.
* **Instant Session Invalidation (Kill-Switch):** Physical card removal triggers immediate cryptographic session termination across the agent and web application.
* **Design & Mockup Compliance:** The user interface adheres strictly to visual mockups provided by the design team, utilizing a modern, clean Windows native look and feel.

---

## 2. Technology Stack & Runtime Decisions

To ensure rapid startup (< 500 ms) and minimal RAM utilization (< 45 MB in background idle), `KILLAgent` avoids heavy application server frameworks (such as Spring Boot) and relies on standard Java runtime capabilities combined with focused, high-performance libraries:

* **Language & Runtime:** Java 21 LTS (or Java 17 LTS).
* **Smart Card & Hardware Subsystem:**
  * `javax.smartcardio` (PC/SC WinSCard integration for instant card insertion/removal detection).
  * `jdk.crypto.cryptoki` (`SunPKCS11` provider for talking to the official RENIEC PKCS#11 `.dll`).
* **Local WebSocket Server:** `org.java-websocket:Java-WebSocket` or lightweight embedded `HttpServer` + WebSocket handler.
* **JSON Serialization:** `com.fasterxml.jackson.core:jackson-databind`.
* **Desktop UI & System Tray:**
  * Modern `Swing` with `com.formdev:flatlaf` (FlatLaf Windows 11 Dark/Light theme) OR `JavaFX` modular runtime.
  * `java.awt.SystemTray` for persistent taskbar presence and dynamic status icons.
* **Environment Configuration:** Support for `.env` files via `io.github.cdimascio:dotenv-java` combined with standard `config.properties`.
* **Packaging & Distribution:** Packaged with `jlink` and `jpackage` to produce a standalone Windows installer (`.msi` / `.exe`) with an embedded stripped JRE (~35 MB).

---

## 3. Environment Configuration (`.env` / `config.properties`)

The agent dynamically adapts its security policies and behavior based on the loaded configuration. The resolution priority is: **System Environment Variables $\rightarrow$ `.env` file $\rightarrow$ `config.properties` default fallback**.

### Environment Schema

```ini
# Environment Profile: 'development' or 'production'
ENVIRONMENT=development

# WebSocket Server Configuration
KILLAGENT_PORT=3000
KILLAGENT_HOST=127.0.0.1
KILLAGENT_SECURE_WSS=true
KILLAGENT_KEYSTORE_PATH=./keystore/loopback.p12
KILLAGENT_KEYSTORE_PASSWORD=changeit

# Zero Trust Security & Anti-CSRF
# Comma-separated list of allowed origins. Wildcards not permitted in production.
ALLOWED_ORIGINS=https://chasca.ong.pe,https://app.chasca.internal,http://localhost:5173,http://localhost:8080

# Hardware & PKI Configuration
# Relative or absolute paths to RENIEC PKCS#11 DLLs (auto-detected if omitted)
RENIEC_PKCS11_DLL_PATH_DNI2=C:\\Windows\\System32\\bit4ipki.dll
RENIEC_PKCS11_DLL_PATH_DNI3=C:\\Windows\\System32\\eps2003csp11.dll

# Development Mock / Sandbox Mode (True = simulates DNIe without physical card reader)
MOCK_HARDWARE_ENABLED=true
MOCK_DNI_SIMULATED=71234567
MOCK_USER_FULL_NAME=JUAN PEREZ GARCIA

# UI Settings
UI_THEME=auto # 'light', 'dark', or 'auto' (sync with Windows theme)
SHOW_BALLOON_NOTIFICATIONS=true
```

---

## 4. Visual Taskbar & System Tray Integration

The agent must provide immediate visual feedback regarding daemon operational health and smart card detection without requiring an open window.

### Dynamic System Tray Icons
The taskbar icon changes dynamically to convey system state:
1. **Gray / Red Dot:** Daemon running, but **no smart card reader detected**.
2. **Orange / Alert:** Reader connected, but **no DNIe card inserted**.
3. **Green / Shield (Active Ready):** DNIe 3.0 inserted and recognized; certificates loaded and ready.
4. **Blue / Pulsing:** Cryptographic operation in progress (PIN prompt or hardware signature calculation).
5. **Purple (Sandbox):** Running in `development` mock mode.

### Taskbar Context Menu Actions
Right-clicking the tray icon surfaces:
* **Header / Status Pill:** Shows connection state, reader model, and masked cardholder DNI (`DNI: *****567`).
* **"Abrir Panel de Diagnóstico" (Open Diagnostics Panel):** Displays PC/SC terminals, PKCS#11 slot status, certificate details, and test challenge verification.
* **"Probar Firma de Prueba" (Test Sign):** Runs a local test signature to verify PIN and chip health.
* **"Conmutar a Modo Sandbox" (Toggle Sandbox):** Visible only when `ENVIRONMENT=development`.
* **"Reiniciar Conexión WebSocket" (Restart WebSocket):** Binds again if port collision occurred.
* **"Salir" (Exit):** Cleanly closes PKCS#11 slots, notifies active WebSockets, and terminates.

---

## 5. Anti-Keylogger Security & Virtual Keypad Specification

To satisfy strict Zero Trust requirements against software keyloggers, screen scrapers, and clipboard interceptors:

### Virtual Scrambled Keypad (On-Screen Keyboard)
* **Randomized Number Layout:** The numerical pad (digits 0 through 9) must be randomly shuffled each time the PIN modal appears. A keylogger recording physical keystrokes receives zero data; a hardware mouse tracker capturing click coordinates cannot deduce the numbers because button positions change randomly across sessions.
* **No Clipboard Support:** The password field completely disables copy, cut, and paste (`TransferHandler` disabled, keystroke bindings intercepted).
* **Physical Keyboard Masking / Optional Bypass:** Users may opt to click the randomized buttons or type on the physical keyboard; if clicked via mouse, physical keyboard events are entirely avoided.
* **Memory Invalidation:** PIN values are stored strictly in `char[]` (never in `java.lang.String`). As soon as the PKCS#11 `KeyStore.load()` or `Signature.sign()` operation finishes (or fails), the array is immediately sanitized:
  ```java
  Arrays.fill(pinBuffer, '\0');
  ```
* **Window Invariants:**
  * Always on Top (`setAlwaysOnTop(true)`).
  * Centered on the active display.
  * Disables window screenshot capture in OS where supported (e.g. `SetWindowDisplayAffinity(WDA_MONITOR)` via JNA).
  * Displays details of the operation requested:
    * For Login: *"Autenticación Institucional Ch'asca (Reto de Identidad)"*.
    * For Signing: Document Title, Hash SHA-256 preview, and Signer Role.

---

## 6. Communication Protocol & WebSocket Specifications

### WebSocket Endpoint: `wss://127.0.0.1:3000` (or `ws://127.0.0.1:3000`)
Every message is a JSON payload adhering to the contracts defined below.

### 6.1 Handshake & Origin Validation
Upon connection request from the browser, `KILLAgent` checks the `Origin` header against `ALLOWED_ORIGINS`. If unauthorized, the connection is closed immediately (`CloseFrame.REFUSE`).

On successful connection, `KILLAgent` sends a `CONNECTED` event:
```json
{
  "type": "CONNECTION_ESTABLISHED",
  "wsConnectionId": "ws-killagent-9921b-4f81",
  "version": "1.0.0",
  "hardwareStatus": {
    "readerPresent": true,
    "cardPresent": true,
    "readerName": "Identiv uTrust 2700 R Smart Card Reader 0",
    "cardType": "DNIE_3_0",
    "isMock": false
  }
}
```

### 6.2 Hardware Event Push Notifications (Unsolicited)
When physical hardware status changes, `KILLAgent` broadcasts to all connected clients:
* **Card Removed (Kill Switch Trigger):**
  ```json
  {
    "type": "CARD_REMOVED",
    "timestamp": "2026-11-01T10:15:30Z"
  }
  ```
* **Card Inserted:**
  ```json
  {
    "type": "CARD_INSERTED",
    "timestamp": "2026-11-01T10:16:05Z",
    "readerName": "Identiv uTrust 2700 R 0"
  }
  ```

### 6.3 Operation: Sign Authentication Challenge (Phase 2 Login & Step-Up)
**Request from Web Frontend:**
```json
{
  "type": "SIGN_AUTH_CHALLENGE",
  "requestId": "req-auth-1002",
  "nonce": "a4f891e204b7c9103f8a12d4e567890123456789abcdef0123456789abcdef01"
}
```

**Response to Web Frontend (Ready for `POST /api/v1/authentication/sign-in`):**
```json
{
  "type": "SIGN_AUTH_CHALLENGE_RESPONSE",
  "requestId": "req-auth-1002",
  "status": "SUCCESS",
  "payload": {
    "nonce": "a4f891e204b7c9103f8a12d4e567890123456789abcdef0123456789abcdef01",
    "signedNonce": "MEQCIAuW...<Base64 signature>...",
    "clientCertificatePem": "-----BEGIN CERTIFICATE-----\nMIIF...<RENIEC Public X.509 Certificate>...\n-----END CERTIFICATE-----",
    "wsConnectionId": "ws-killagent-9921b-4f81",
    "metadata": {
      "dni": "71234567",
      "fullName": "JUAN PEREZ GARCIA",
      "certificateSerialNumber": "4A12B890F1",
      "validTo": "2028-06-15T23:59:59Z"
    }
  }
}
```

### 6.4 Operation: Sign Document Digest (PAdES-LTV Digital Signature)
**Request from Web Frontend:**
```json
{
  "type": "SIGN_DOCUMENT_DIGEST",
  "requestId": "req-doc-5501",
  "slotId": "b18f8101-5e92-4293-8b7c-7a54911f32a0",
  "documentHash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "documentTitle": "Convenio de Cooperación Técnica 2026.pdf",
  "signerRole": "SIGNER"
}
```

**Response to Web Frontend (Ready for `RegisterDigitalSignatureCommand`):**
```json
{
  "type": "SIGN_DOCUMENT_DIGEST_RESPONSE",
  "requestId": "req-doc-5501",
  "status": "SUCCESS",
  "payload": {
    "slotId": "b18f8101-5e92-4293-8b7c-7a54911f32a0",
    "certificateDni": "71234567",
    "documentHash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "signatureValue": "Rz1m...<Base64 PAdES digital signature>...",
    "signerSubjectDn": "CN=JUAN PEREZ GARCIA, SERIALNUMBER=DNI71234567, O=RENIEC, C=PE",
    "certificateSerialNumber": "4A12B890F1",
    "clientCertificatePem": "-----BEGIN CERTIFICATE-----\n..."
  }
}
```

### 6.5 Error Response Structure
```json
{
  "type": "ERROR",
  "requestId": "req-auth-1002",
  "errorCode": "PIN_INCORRECT", // PIN_INCORRECT, PIN_LOCKED, CARD_NOT_PRESENT, USER_CANCELLED, PKCS11_ERROR
  "message": "El PIN ingresado es incorrecto. Quedan 2 intentos restantes.",
  "attemptsRemaining": 2
}
```

---

## 7. PKCS#11 Integration & Certificate Differentiator

The DNIe 3.0 chip hosts two independent certificate pairs. The agent must parse their KeyUsage and select the appropriate certificate depending on the requested operation:

1. **Authentication Certificate:**
   * **Key Usage:** `Digital Signature` (no Non-Repudiation).
   * **Target:** Challenge verification for login (`SIGN_AUTH_CHALLENGE`) and Step-Up PIN actions.
2. **Signature Certificate (Digital Signature & Non-Repudiation):**
   * **Key Usage:** `Non Repudiation` / `Content Commitment`.
   * **Target:** Formal PAdES document sealing (`SIGN_DOCUMENT_DIGEST`).

### PKCS#11 Dynamic Driver Configuration
The agent constructs the `SunPKCS11` configuration dynamically in memory:

```java
String pkcs11Config = """
    name = DNIe3
    library = %s
    slotListIndex = 0
    """.formatted(detectedDllPath);

Provider sunPkcs11 = Security.getProvider("SunPKCS11").configure(new ByteArrayInputStream(pkcs11Config.getBytes(StandardCharsets.UTF_8)));
Security.addProvider(sunPkcs11);
```

---

## 8. Mock / Sandbox Mode for Development Without Hardware

When `ENVIRONMENT=development` and no physical reader is attached, the agent can run in **Mock / Sandbox Mode**:
* Emulates card insertion/removal triggers via a debug GUI or tray menu item.
* Uses an in-memory Bouncy Castle 2048-bit RSA key pair.
* Generates synthetic X.509 certificates matching RENIEC DN formats:
  `CN=MOCK JUAN PEREZ, SERIALNUMBER=DNI71234567, O=RENIEC, C=PE`.
* Validates user-entered test PIN (e.g. default `"123456"` or randomized input).
* Generates mathematically valid RSA signatures that the backend's `ReniecDniePkiValidationAdapter` can verify using its public key or sandbox prefix (`DNIE_CERT_DNI_` / `SIGNED_NONCE_`).

---

## 9. Implementation Checklist for the Builder Agent

* [ ] Initialize Maven/Gradle project for Java 21 LTS with modular dependencies.
* [ ] Implement configuration loader supporting `.env` and `config.properties`.
* [ ] Implement `javax.smartcardio` terminal monitor thread with card insertion/removal events.
* [ ] Implement `SunPKCS11` bridge with automatic Windows DLL path discovery for RENIEC DNIe.
* [ ] Build the loopback WebSocket server (`127.0.0.1:3000`) with Origin validation.
* [ ] Implement the Anti-Keylogger virtual keyboard modal (Swing FlatLaf or JavaFX) with randomized numeric buttons and `char[]` sanitization.
* [ ] Implement the dynamic System Tray icon with status changes (Connected, Disconnected, Busy, Mock).
* [ ] Implement the development sandbox mode (Bouncy Castle mock key generator).
* [ ] Add `jpackage` configuration script to produce Windows `.msi` installers with embedded minimal JRE.
* [ ] Align and verify all JSON message formats against Ch'asca backend contracts (`SignInResource`, `RegisterDigitalSignatureCommand`).

