# KILLAgent: Zero Trust Hardware Anchor & PKCS#11 Desktop Agent

`KILLAgent` es un daemon local de escritorio ultra liviano (< 45 MB RAM en reposo, arranque < 500 ms) construido en **Java 21 LTS** para estaciones de trabajo Windows. Actúa como el ancla física de hardware criptográfico de la plataforma **Ch'asca** (*Zero Trust Document Management & Digital Signature Platform*).

Media operaciones criptográficas entre el frontend web (React SPA) y tarjetas inteligentes físicas (**DNI Electrónico Peruano — DNIe 3.0 IDEMIA y DNIe 2.0 / PKCS#11 de RENIEC**) a través de un servidor WebSocket / WSS exclusivo en loopback (`127.0.0.1:3000`).

---

## 🏛️ Arquitectura e Invariantes de Seguridad Zero Trust

1. **Aislamiento Estricto por Dispositivo (Loopback-Only & Single-Instance):**
   * Verificación estricta de red (`InetAddress.isLoopbackAddress()`): bloquea con `SecurityException` cualquier intento de enlace a `0.0.0.0` o interfaces LAN.
   * Bloqueo a nivel de SO mediante `SingleInstanceLock` (`FileChannel.tryLock()` en `%LOCALAPPDATA%\Chasca\KILLAgent\killagent.lock`) para evitar colisiones de puerto o sesiones PC/SC concurrentes.
   * Soporte nativo **WSS (TLS 1.3/1.2)** vía `LoopbackSslContextFactory` con auto-aprovisionamiento de keystore PKCS#12 (`CN=127.0.0.1`, SAN `IP:127.0.0.1`, `DNS:localhost`).
2. **Defensa Anti-CSWSH (Validación RFC 6454 de `Origin` en Doble Capa):**
   * `OriginValidator` normaliza esquema, host y puerto, bloqueando ataques de spoofing de prefijo (`https://chasca.ong.pe.evil.com`), orígenes `null` y wildcards (`*`) en producción, rechazando conexiones ilegítimas antes del upgrade HTTP 101.
3. **Aislamiento Total del PIN y Arquitectura Zero-String en Memoria:**
   * El PIN del ciudadano **jamás** viaja por la red ni se almacena en objetos inmutables `java.lang.String` ni en modelos `Document` de Swing.
   * `AntiKeyloggerKeypadDialog` mantiene los dígitos únicamente en un `char[]` pre-asignado, mostrando máscaras estáticas (`●`), barajando el teclado numérico en pantalla con `SecureRandom` en cada sesión, bloqueando el portapapeles y ofreciendo bloqueo opcional del teclado físico (modo solo mouse).
   * Protección contra capturas de pantalla y screen-scrapers a nivel kernel de Windows 10/11 mediante `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE / WDA_MONITOR)` vía JNA.
   * Limpieza inmediata en sitio (`Arrays.fill(pin, '\0')`) vía `PinBuffer` y cierre de sesión hardware (`AuthProvider.logout()` / `C_Logout`) al concluir cada operación.
4. **Kill-Switch Instantáneo por Retiro Físico (`SCardGetStatusChange`):**
   * `CardReaderManager` bloquea nativamente sobre eventos `WinSCard` (`terminals.waitForChange`), detectando la extracción de la tarjeta en < 10 ms con 0% de uso de CPU en reposo.
   * Al retirar el DNIe: aborta y limpia inmediatamente cualquier modal de PIN abierto, descarga la sesión `SunPKCS11` y emite el broadcast `CARD_REMOVED` a todas las sesiones web conectadas.
5. **Conformidad Legal PAdES-LTV & Diferenciación de Certificados RENIEC (Ley N° 27269):**
   * Selección estricta por `KeyUsage` X.509: Certificado de **Autenticación** (`digitalSignature`) para `SIGN_AUTH_CHALLENGE` y Certificado de **No-Repudio** (`nonRepudiation / contentCommitment`) para `SIGN_DOCUMENT_DIGEST` (sin degradación silenciosa).
   * Encapsulamiento DER `DigestInfo` (RFC 8017 SHA-256) firmado con `NONEwithRSA` (`CKM_RSA_PKCS`), produciendo firmas matemáticamente idénticas a `SHA256withRSA` sobre el documento PDF original sin transferir el PDF completo al bus de la tarjeta inteligente.

---

## 📁 Estructura del Proyecto

```text
Killa/
├── KILLAGENT_SPECIFICATION.md            # Especificación arquitectónica oficial
├── FRONTEND_INTEGRATION_GUIDE.md         # Guía detallada y SDK TypeScript para el frontend web
├── pom.xml                               # Build Maven Java 21 LTS + Shade Fat JAR
├── package-windows.ps1                   # Pipeline jlink (~35 MB JRE) + jpackage (.msi/.exe)
├── .env / .env.example                   # Configuración de entorno local
└── src/
    ├── main/
    │   ├── resources/
    │   │   ├── config.properties         # Propiedades fallback por defecto
    │   │   └── assets/                   # Sistema visual Celestial Cyber-Andean (.svg / .png)
    │   │       ├── icons/                # app-icon, tray-card-ready, tray-no-card, tray-no-reader, tray-busy, tray-sandbox
    │   │       ├── images/               # brand-logo, shield-badge, chasca-star-emblem, chasca-wordmark
    │   │       └── mockups/              # Espacio para especificaciones visuales UI
    │   └── java/pe/ong/chasca/killagent/
    │       ├── KillAgentApplication.java           # Bootstrap, SingleInstanceLock, Windows Theme Sync & Lifecycle
    │       ├── config/
    │       │   ├── AgentConfig.java                # Configuración inmutable con invariantes Zero Trust
    │       │   └── ConfigurationLoader.java        # Resolución: System Env -> .env -> config.properties
    │       ├── security/
    │       │   ├── OriginValidator.java            # Validación estricta RFC 6454 de cabecera Origin
    │       │   ├── SingleInstanceLock.java         # Lock exclusivo de proceso en sistema operativo
    │       │   └── LoopbackSslContextFactory.java  # Contexto TLS 1.3/1.2 y auto-provisión PKCS#12 loopback
    │       ├── hardware/
    │       │   ├── CardType.java                   # NONE, DNIE_2_0, DNIE_3_0, UNKNOWN
    │       │   ├── HardwareStatus.java             # Snapshot inmutable del estado del lector/chip
    │       │   ├── HardwareListener.java           # Observador de eventos hot-plug y Kill-Switch
    │       │   ├── CardReaderManager.java          # Monitor reactivo WinSCard PC/SC + simulador Sandbox
    │       │   ├── pkcs11/Pkcs11Bridge.java        # Sesiones SunPKCS11 multi-slot con C_Logout automático
    │       │   └── mock/MockHardwareService.java   # Emulador Bouncy Castle RSA-2048 con bloqueo a 3 intentos
    │       ├── crypto/
    │       │   ├── PinBuffer.java                  # Contenedor char[] AutoCloseable zero-copy
    │       │   ├── CertificatePurpose.java         # AUTHENTICATION vs SIGNATURE (Non-Repudiation)
    │       │   ├── RsaDigestInfoHelper.java        # Framing ASN.1 DER DigestInfo RFC 8017 (SHA-256)
    │       │   ├── CryptoOperationException.java   # Traducción de fallos CKR_* PKCS#11 a ErrorCodes
    │       │   ├── AuthChallengeResult.java
    │       │   ├── DocumentDigestResult.java
    │       │   └── CryptoService.java              # Mediador criptográfico principal
    │       ├── server/
    │       │   ├── KillAgentWebSocketServer.java   # Servidor Loopback concurrente con worker criptográfico
    │       │   └── dto/                            # Contratos JSON alineados con backend Ch'asca
    │       └── ui/
    │           ├── AssetManager.java               # Cargador vectorial SVG (FlatSVGIcon/JSVG) + PNG
    │           ├── TrayIconFactory.java            # Renderizador procedural de respaldo
    │           ├── PinPromptProvider.java          # Abstracción desacoplada de captura segura de PIN
    │           ├── SwingPinPromptProvider.java     # Proveedor modal EDT-safe cancelable por Kill-Switch
    │           ├── AntiKeyloggerKeypadDialog.java  # Teclado virtual aleatorizado Zero-String + JNA WDA
    │           ├── DiagnosticsDialog.java          # Dashboard PC/SC, PKCS#11 y simulador de eventos Sandbox
    │           └── SystemTrayManager.java          # Integración con bandeja de Windows 11
    └── test/java/pe/ong/chasca/killagent/
        ├── security/SecurityInvariantsTest.java
        ├── crypto/CryptoServicePadesAndAuthTest.java
        ├── crypto/PinBufferTest.java
        ├── hardware/mock/MockHardwareServiceTest.java
        ├── server/KillAgentWebSocketIntegrationTest.java
        ├── server/WebSocketProtocolSerializationTest.java
        └── ui/AssetManagerTest.java
```

---

## ⚙️ Variables de Configuración (`.env` / `config.properties`)

Prioridad de carga: **Variables de Entorno del SO $\rightarrow$ `.env` $\rightarrow$ `config.properties`**.

```ini
ENVIRONMENT=development
KILLAGENT_PORT=3000
KILLAGENT_HOST=127.0.0.1
KILLAGENT_SECURE_WSS=false
KILLAGENT_KEYSTORE_PATH=./keystore/loopback.p12
KILLAGENT_KEYSTORE_PASSWORD=changeit

ALLOWED_ORIGINS=https://chasca.ong.pe,https://app.chasca.internal,http://localhost:5173,http://localhost:8080

# Middleware oficial IDEMIA IDPlugClassic (DNIe 3.0) y Bit4id (DNIe 2.0)
RENIEC_PKCS11_DLL_PATH_DNI3=C:\\Program Files\\IDEMIA\\IDPlugClassic\\DLLs\\idplug-pkcs11.dll
RENIEC_PKCS11_DLL_PATH_DNI2=C:\\Windows\\System32\\bit4ipki.dll

# Modo Sandbox (solo permitido en development; ingresar PIN '000000' simula PIN_INCORRECT / PIN_LOCKED)
MOCK_HARDWARE_ENABLED=true
MOCK_DNI_SIMULATED=71234567
MOCK_USER_FULL_NAME=JUAN PEREZ GARCIA

# Modo de firma de digest: PADES_DIGEST_INFO (default RFC 8017), SHA256_OVER_HASH_BYTES, SHA256_OVER_HEX_STRING
DOCUMENT_DIGEST_SIGN_MODE=PADES_DIGEST_INFO

# Tema UI: 'auto' (sincroniza con Registro de Windows 11), 'dark' o 'light'
UI_THEME=auto
SHOW_BALLOON_NOTIFICATIONS=true
```

---

## 🚀 Compilación, Pruebas y Empaquetado Nativo

### 1. Ejecutar Suite Completa de Pruebas Unitarias y de Integración
```powershell
mvn clean test
```

### 2. Construir Fat JAR Ejecutable
```powershell
mvn clean package
java -jar target\killagent-1.0.0-SNAPSHOT.jar
```

### 3. Generar Distribución Nativa Windows con JRE Reducido (`jlink` + `jpackage`)
```powershell
# Generar imagen portable autónoma (no requiere WiX Toolset):
.\package-windows.ps1 -PackageType app-image

# Generar instalador corporativo Windows (.msi, requiere WiX Toolset 3.x):
.\package-windows.ps1 -PackageType msi
```
