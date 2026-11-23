# Distribución, Empaquetado y Actualizaciones Seguras de KILLAgent

Este documento describe el flujo estándar para **publicar** y **recibir** actualizaciones de `KILLAgent` siguiendo buenas prácticas de seguridad y distribución en estaciones de trabajo Windows.

---

## 1. Artefactos de Distribución Generados

El script [`package-windows.ps1`](../package-windows.ps1) compila el agente, genera un runtime mínimo de Java 21 con `jlink` (incluyendo `java.smartcardio`, `jdk.crypto.cryptoki` y `java.net.http`) y produce en `dist/`:

| Artefacto | Uso recomendado |
| :--- | :--- |
| `KILLAgent-<version>.msi` | Instalador estándar Windows per-user (`%LOCALAPPDATA%\Programs\KILLAgent`) con accesos directos y `UpgradeCode` fijo para actualizaciones limpias in-place. *(Requiere WiX Toolset v3.x)* |
| `KILLAgent-<version>-windows-x64-portable.zip` | Paquete autónomo portable listo para descomprimir y ejecutar (`KILLAgent\KILLAgent.exe`) sin depender de WiX ni JDK instalado. |
| `killagent-<version>.jar` | Fat JAR ejecutable multi-release (`java -jar`). |
| `SHA256SUMS.txt` | Sumas SHA-256 verificables de todos los archivos publicados. |
| `update-manifest.json` | Manifiesto estructurado (`schemaVersion: 1`) consumido por los agentes instalados para comprobar, verificar y descargar nuevas versiones. |

---

## 2. Cómo Publicar Actualizaciones (Emisor / Equipo Técnico)

### 2.1 Configurar Clave Ed25519 de Firma de Manifiestos (Recomendado)

La firma **Ed25519** evita que un compromiso de hosting o CDN altere el manifiesto de actualización:

1. Genera un par de claves una sola vez:
   ```powershell
   .\scripts\generate-update-keys.ps1
   ```
2. Guarda `UPDATE_SIGNING_PRIVATE_KEY` en GitHub $\rightarrow$ *Settings* $\rightarrow$ *Secrets and variables* $\rightarrow$ *Actions* $\rightarrow$ *Repository secrets*.
3. Coloca `UPDATE_SIGNING_PUBLIC_KEY`:
   * Como Variable de repositorio en GitHub Actions (`UPDATE_SIGNING_PUBLIC_KEY`) para verificar cada build en CI/CD.
   * En los clientes desplegados (`UPDATE_SIGNING_PUBLIC_KEY=...` en `%LOCALAPPDATA%\Chaska\KILLAgent\.env` o en `src/main/resources/config.properties`).

### 2.2 Firma Authenticode de Ejecutables Windows (Opcional)

Para eliminar advertencias de Windows SmartScreen en entornos corporativos, agrega estos secretos en GitHub (o variables de entorno locales al ejecutar `package-windows.ps1`):

* `WINDOWS_CERT_PFX_BASE64`: Certificado `.pfx` de firma de código codificado en Base64 (o `WINDOWS_CERT_PFX_PATH` en local).
* `WINDOWS_CERT_PASSWORD`: Contraseña del archivo `.pfx`.

Cuando están presentes, `package-windows.ps1` firma automáticamente `KILLAgent.exe` y `KILLAgent-<version>.msi` usando `signtool.exe` con SHA-256 y sello de tiempo RFC 3161.

### 2.3 Publicar una Nueva Versión con GitHub Releases

1. Ejecuta el asistente desde la rama `main` limpia:
   ```powershell
   .\scripts\publish-release.ps1 -Version 1.0.1 -ReleaseNotes "Correcciones de estabilidad PKCS#11" -Push
   ```
   *(También puedes disparar manualmente el workflow **KILLAgent Release & Windows Installer** en GitHub Actions desde `workflow_dispatch`).*
2. El workflow [`.github/workflows/release.yml`](../.github/workflows/release.yml):
   * Ejecuta todas las pruebas (`mvn -B clean test`).
   * Compila el `.msi`, el `.zip` portable, `SHA256SUMS.txt` y `update-manifest.json`.
   * Firma el manifiesto con Ed25519 y publica automáticamente el GitHub Release con el tag `v<version>`.

---

## 3. Cómo Reciben y Verifican las Actualizaciones los Clientes

Cada instancia de `KILLAgent` instalada realiza lo siguiente de forma segura:

1. **Comprobación sin bloqueo:** 15 segundos después de arrancar (preservando el arranque `< 500 ms`) y luego cada `UPDATE_CHECK_INTERVAL_HOURS` (por defecto `6h`), `UpdateService` consulta `UPDATE_MANIFEST_URL` siempre que no haya una operación PIN/DNIe en curso. También se puede comprobar manualmente desde el icono en bandeja $\rightarrow$ **Buscar Actualizaciones...** o desde el Panel de Diagnóstico.
2. **Validación de origen y redirecciones:** Solo se aceptan URLs `https://` cuyo host (y cualquier redirección HTTP 30x) pertenezca a `UPDATE_ALLOWED_HOSTS`.
3. **Comparación SemVer y piso mínimo:** `SemanticVersion` compara versiones estrictas (`1.0.1 > 1.0.0`). Si el manifiesto marca `mandatory: true` o la versión instalada es menor que `minimumSupportedVersion`, la interfaz destaca la actualización como obligatoria.
4. **Verificación criptográfica en dos niveles:**
   * Si `UPDATE_SIGNING_PUBLIC_KEY` está configurada, se verifica la firma **Ed25519** sobre el payload canónico del manifiesto antes de ofrecer la actualización.
   * Tras descargar el instalador en `%LOCALAPPDATA%\Chaska\KILLAgent\updates\<archivo>.part`, `UpdateVerifier` valida tamaño exacto en bytes y hash **SHA-256** en tiempo constante; ante cualquier discrepancia elimina el `.part` y aborta.
5. **Instalación limpia e in-place:**
   * **Instalación MSI:** Cierra la instancia activa para liberar el `SingleInstanceLock` y archivos en uso, ejecuta `msiexec /i <paquete>.msi /passive /norestart /l*v <log>` en segundo plano y relanza automáticamente `KILLAgent.exe`.
   * **Instalación Portable:** Extrae el `.zip` verificado, reemplaza los binarios tras finalizar el PID actual y relanza `KILLAgent.exe`.

---

## 4. Diagnóstico y Logs Locales

* **Directorio de datos del usuario:** `%LOCALAPPDATA%\Chaska\KILLAgent\`
  * `.env` — Overrides locales del usuario/estación (opcional).
  * `logs\killagent.log` — Log rotativo de ejecución (cuando corre sin consola).
  * `logs\update-<version>.log` — Log de instalación MSI en actualizaciones.
  * `updates\` — Instaladores descargados y verificados por SHA-256.
