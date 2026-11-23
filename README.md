# KILLAgent: Zero Trust Hardware Anchor & PKCS#11 Desktop Agent

`KILLAgent` es un daemon local de escritorio ultra liviano (< 45 MB RAM en reposo, arranque < 500 ms) construido en **Java 21 LTS** para estaciones de trabajo Windows. Actúa como el ancla física de hardware criptográfico de la plataforma **Ch'aska** (*Zero Trust Document Management & Digital Signature Platform*).

Media operaciones criptográficas entre el frontend web (React SPA) y tarjetas inteligentes físicas (**DNI Electrónico Peruano — DNIe 3.0 IDEMIA y DNIe 2.0 / PKCS#11 de RENIEC**) a través de un servidor WebSocket / WSS exclusivo en loopback (`127.0.0.1:3000`).

---

## Arquitectura e Invariantes de Seguridad Zero Trust

1. **Aislamiento Estricto por Dispositivo (Loopback-Only & Single-Instance):**
   * Verificación estricta de red (`InetAddress.isLoopbackAddress()`): bloquea con `SecurityException` cualquier intento de enlace a `0.0.0.0` o interfaces LAN.
   * Bloqueo a nivel de SO mediante `SingleInstanceLock` (`FileChannel.tryLock()` en `%LOCALAPPDATA%\Chaska\KILLAgent\killagent.lock`) para evitar colisiones de puerto o sesiones PC/SC concurrentes.
   * Soporte nativo **WSS (TLS 1.3/1.2)** vía `LoopbackSslContextFactory` con auto-aprovisionamiento de keystore PKCS#12 (`CN=127.0.0.1`, SAN `IP:127.0.0.1`, `DNS:localhost`).
2. **Defensa Anti-CSWSH (Validación RFC 6454 de `Origin` en Doble Capa):**
   * `OriginValidator` normaliza esquema, host y puerto, bloqueando ataques de spoofing de prefijo (`https://chaska.ong.pe.evil.com`), orígenes `null` y wildcards (`*`) en producción, rechazando conexiones ilegítimas antes del upgrade HTTP 101.
3. **Aislamiento Total del PIN y Arquitectura Zero-String en Memoria:**
   * El PIN del ciudadano **jamás** viaja por la red ni se almacena en objetos inmutables `java.lang.String` ni en modelos `Document` de Swing.
   * `AntiKeyloggerKeypadDialog` mantiene los dígitos únicamente en un `char[]` pre-asignado, mostrando máscaras estáticas (`●`), barajando el teclado numérico en pantalla con `SecureRandom` en cada sesión, bloqueando el portapapeles y ofreciendo bloqueo opcional del teclado físico (modo solo mouse).
   * Protección contra capturas de pantalla y screen-scrapers a nivel kernel de Windows 10/11 mediante `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE / WDA_MONITOR)` vía JNA.
   * Limpieza inmediata en sitio (`Arrays.fill(pin, '\0')`) vía `PinBuffer` y cierre de sesión hardware (`AuthProvider.logout()` / `C_Logout`) al concluir cada operación.
4. **Kill-Switch Instantáneo por Retiro Físico (`SCardGetStatusChange`):**
   * `CardReaderManager` bloquea nativamente sobre eventos `WinSCard` (`SCardGetStatusChange`), detectando la extracción de la tarjeta en < 10 ms con 0% de uso de CPU en reposo.
   * Al retirar el DNIe: aborta y limpia inmediatamente cualquier modal de PIN abierto, descarga la sesión `SunPKCS11` y emite el broadcast `CARD_REMOVED` a todas las sesiones web conectadas.
5. **Conformidad Legal PAdES-LTV & Diferenciación de Certificados RENIEC (Ley N° 27269):**
   * Selección estricta por `KeyUsage` X.509: Certificado de **Autenticación** (`digitalSignature`) para `SIGN_AUTH_CHALLENGE` y Certificado de **No-Repudio** (`nonRepudiation / contentCommitment`) para `SIGN_DOCUMENT_DIGEST`.
   * Encapsulamiento DER `DigestInfo` (RFC 8017 SHA-256) firmado con `NONEwithRSA` (`CKM_RSA_PKCS`), produciendo firmas matemáticamente idénticas a `SHA256withRSA` sobre el documento PDF original sin transferir el PDF completo al bus de la tarjeta inteligente.
6. **Distribución Empaquetada y Auto-Actualización Segura:**
   * Distribución autónoma Windows x64 (`.msi` per-user o `.zip` portátil) con runtime Java 21 reducido vía `jlink` + `jpackage`.
   * Sistema integrado de actualizaciones (`UpdateService`, `UpdateVerifier`, `UpdateInstaller`, `UpdateDialog`) con comprobación periódica en segundo plano, transporte estricto **HTTPS** contra hosts permitidos, verificación **SHA-256** de artefactos, soporte de firma criptográfica **Ed25519** sobre `update-manifest.json` y actualización desatendida segura con logs persistentes en `%LOCALAPPDATA%\Chaska\KILLAgent\logs`.

---

## Estructura del Proyecto

```text
Killa/
├── KILLAGENT_SPECIFICATION.md            # Especificación arquitectónica oficial
├── FRONTEND_INTEGRATION_GUIDE.md         # Guía detallada y SDK TypeScript para el frontend web
├── docs/RELEASE_AND_UPDATES.md           # Guía profesional de empaquetado, firma y releases OTA
├── pom.xml                               # Build Maven Java 21 LTS + Shade Fat JAR
├── package-windows.ps1                   # Pipeline jlink + jpackage (.msi/.zip) + manifest + firma
├── scripts/
│   ├── ManifestSigner.java               # Generación/firma/verificación Ed25519 de manifiestos
│   ├── generate-update-keys.ps1          # Helper para generar par de claves Ed25519
│   └── publish-release.ps1               # Automatización de bump SemVer, test y tag Git
├── .github/workflows/
│   ├── ci.yml                            # CI: test + build portable + smoke check
│   └── release.yml                       # CD: MSI + Portable ZIP + Update Manifest + GitHub Release
└── src/main/java/pe/ong/chasca/killagent/
    ├── KillAgentApplication.java
    ├── config/                           # AgentConfig, ConfigurationLoader, AppPaths, AgentVersion
    ├── security/                         # OriginValidator, SingleInstanceLock, LoopbackSslContextFactory
    ├── system/                           # LoggingBootstrap, WindowsStartupManager
    ├── hardware/                         # CardReaderManager, WinSCardReaderProbe, Pkcs11Bridge
    ├── crypto/                           # CryptoService, PinBuffer, RsaDigestInfoHelper
    ├── server/                           # KillAgentWebSocketServer + contratos JSON
    ├── update/                           # SemanticVersion, UpdateManifest, UpdateVerifier, UpdateService, UpdateInstaller
    └── ui/                               # SystemTrayManager, DiagnosticsDialog, UpdateDialog, AntiKeyloggerKeypadDialog
```

---

## Variables de Configuración (`.env` / `config.properties`)

Prioridad de carga: **Variables de Entorno del SO $\rightarrow$ `.env` local $\rightarrow$ `%LOCALAPPDATA%\Chaska\KILLAgent\.env` $\rightarrow$ `/config.properties`**.

```ini
ENVIRONMENT=production
KILLAGENT_PORT=3000
KILLAGENT_HOST=127.0.0.1
KILLAGENT_SECURE_WSS=false
KILLAGENT_KEYSTORE_PASSWORD=changeit

ALLOWED_ORIGINS=https://chaska.ong.pe,https://*.chaska.ong.pe,https://*.chaska.ngo,https://app.chaska.internal,https://*.workers.dev,https://*.pages.dev,http://localhost:5173,http://127.0.0.1:5173

RENIEC_PKCS11_DLL_PATH_DNI3=C:\\Program Files\\IDEMIA\\IDPlugClassic\\DLLs\\idplug-pkcs11.dll
RENIEC_PKCS11_DLL_PATH_DNI2=C:\\Windows\\System32\\bit4ipki.dll

DOCUMENT_DIGEST_SIGN_MODE=PADES_DIGEST_INFO
UI_THEME=auto
SHOW_BALLOON_NOTIFICATIONS=true

# Auto-actualizaciones
UPDATE_ENABLED=true
UPDATE_AUTO_CHECK_ENABLED=true
UPDATE_CHANNEL=stable
UPDATE_MANIFEST_URL=https://github.com/KiwixArc/KillAgent/releases/latest/download/update-manifest.json
UPDATE_CHECK_INTERVAL_HOURS=6
UPDATE_SIGNING_PUBLIC_KEY=
UPDATE_ALLOWED_HOSTS=github.com,objects.githubusercontent.com,release-assets.githubusercontent.com,api.github.com
```

---

## Compilación, Pruebas y Empaquetado Nativo

### 1. Ejecutar Suite Completa de Pruebas
```powershell
mvn clean test
```

### 2. Construir Fat JAR Ejecutable
```powershell
mvn clean package
java -jar target\killagent-1.0.0.jar --version
```

### 3. Generar Distribución Windows Lista para Distribuir
```powershell
# Portable ZIP + app-image + Fat JAR + SHA256SUMS.txt + update-manifest.json:
.\package-windows.ps1 -PackageType portable

# Instalador .msi + Portable ZIP + Manifest completo (requiere WiX Toolset v3.x):
.\package-windows.ps1 -PackageType all
```

Para detalles completos de publicación de versiones, firma Ed25519/Authenticode y despliegue OTA, consulta [docs/RELEASE_AND_UPDATES.md](docs/RELEASE_AND_UPDATES.md).
