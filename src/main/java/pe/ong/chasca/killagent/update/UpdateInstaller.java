package pe.ong.chasca.killagent.update;

import com.sun.jna.platform.win32.Advapi32Util;
import com.sun.jna.platform.win32.WinReg;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pe.ong.chasca.killagent.config.AppPaths;

import java.awt.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Locale;
import java.util.Optional;

/**
 * Coordinates safe handoff from the running KILLAgent process to a detached
 * PowerShell updater that applies a verified .msi upgrade or portable .zip swap
 * once the current process releases its SingleInstanceLock and file handles.
 */
public final class UpdateInstaller {

    private static final Logger logger = LoggerFactory.getLogger(UpdateInstaller.class);
    private static final String[] UNINSTALL_REG_ROOTS = {
            "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            "Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
    };

    public enum LaunchMode {
        MSI_INSTALLED,
        PORTABLE_EXE,
        JAR_OR_DEV
    }

    private UpdateInstaller() {
    }

    public static LaunchMode detectLaunchMode() {
        Optional<String> cmdOpt = ProcessHandle.current().info().command();
        if (cmdOpt.isEmpty()) {
            return LaunchMode.JAR_OR_DEV;
        }
        String cmd = cmdOpt.get().trim();
        if (!cmd.toLowerCase(Locale.ROOT).endsWith("killagent.exe")) {
            return LaunchMode.JAR_OR_DEV;
        }

        if (isInstalledViaMsiRegistry()) {
            return LaunchMode.MSI_INSTALLED;
        }
        return LaunchMode.PORTABLE_EXE;
    }

    public static boolean isMsiInstalled() {
        return detectLaunchMode() == LaunchMode.MSI_INSTALLED;
    }

    /**
     * Applies a cryptographically verified update artifact (.msi or .zip).
     *
     * @return true if an automated installer/relaunch was scheduled and {@code shutdownCallback} was invoked;
     *         false if manual intervention is required (e.g. running directly from {@code java -jar}), in which
     *         case the containing folder is opened for the user.
     */
    public static boolean applyVerifiedUpdate(
            Path verifiedArtifact,
            String targetVersion,
            Runnable shutdownCallback
    ) throws IOException {
        String nameLower = verifiedArtifact.getFileName().toString().toLowerCase(Locale.ROOT);
        LaunchMode launchMode = detectLaunchMode();
        long currentPid = ProcessHandle.current().pid();

        if (nameLower.endsWith(".msi")) {
            Path exePath = resolveCurrentExePath().orElse(null);
            String relaunchExe = exePath != null ? exePath.toAbsolutePath().toString() : "";
            Path logsDir = AppPaths.logsDir();
            Files.createDirectories(logsDir);
            String safeVer = sanitizeFileToken(targetVersion);
            Path msiLog = logsDir.resolve("update-" + safeVer + ".log");
            Path script = writeMsiUpdateScript(currentPid, verifiedArtifact, msiLog, relaunchExe);
            launchDetachedPowerShell(script);
            logger.info("Scheduled detached MSI upgrade to v{} (PID wait={}); shutting down active daemon.", targetVersion, currentPid);
            if (shutdownCallback != null) {
                shutdownCallback.run();
            }
            return true;
        }

        if (nameLower.endsWith(".zip") && launchMode == LaunchMode.PORTABLE_EXE) {
            Path exePath = resolveCurrentExePath()
                    .orElseThrow(() -> new IOException("No se pudo localizar el ejecutable portátil KILLAgent.exe."));
            Path installDir = exePath.toAbsolutePath().getParent();
            Path script = writePortableZipSwapScript(currentPid, verifiedArtifact, installDir, exePath);
            launchDetachedPowerShell(script);
            logger.info("Scheduled detached portable ZIP upgrade to v{} in {}; shutting down active daemon.", targetVersion, installDir);
            if (shutdownCallback != null) {
                shutdownCallback.run();
            }
            return true;
        }

        // Running from JAR / IDE: open verified artifact location for manual launch or installation
        openInExplorer(verifiedArtifact.getParent());
        return false;
    }

    private static Optional<Path> resolveCurrentExePath() {
        return ProcessHandle.current().info().command()
                .map(String::trim)
                .filter(cmd -> cmd.toLowerCase(Locale.ROOT).endsWith(".exe"))
                .map(Paths::get)
                .filter(Files::isRegularFile);
    }

    private static boolean isInstalledViaMsiRegistry() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (!os.contains("win")) {
            return false;
        }
        return hasKillAgentUninstallKey(WinReg.HKEY_CURRENT_USER)
                || hasKillAgentUninstallKey(WinReg.HKEY_LOCAL_MACHINE);
    }

    private static boolean hasKillAgentUninstallKey(WinReg.HKEY root) {
        for (String base : UNINSTALL_REG_ROOTS) {
            try {
                if (!Advapi32Util.registryKeyExists(root, base)) {
                    continue;
                }
                String[] subkeys = Advapi32Util.registryGetKeys(root, base);
                for (String sub : subkeys) {
                    String fullPath = base + "\\" + sub;
                    if (Advapi32Util.registryValueExists(root, fullPath, "DisplayName")) {
                        String displayName = Advapi32Util.registryGetStringValue(root, fullPath, "DisplayName");
                        if ("KILLAgent".equalsIgnoreCase(displayName != null ? displayName.trim() : "")) {
                            return true;
                        }
                    }
                }
            } catch (Throwable ignored) {
            }
        }
        return false;
    }

    private static Path writeMsiUpdateScript(
            long pid,
            Path msiFile,
            Path logFile,
            String relaunchExePath
    ) throws IOException {
        Path updatesDir = AppPaths.updatesDir();
        Files.createDirectories(updatesDir);
        Path script = updatesDir.resolve("apply-update.ps1");

        String escapedMsi = escapePsSingleQuote(msiFile.toAbsolutePath().toString());
        String escapedLog = escapePsSingleQuote(logFile.toAbsolutePath().toString());
        String escapedExe = escapePsSingleQuote(relaunchExePath);

        String content = """
                $ErrorActionPreference = 'Stop'
                $targetPid = %d
                for ($i = 0; $i -lt 60; $i++) {
                    if (-not (Get-Process -Id $targetPid -ErrorAction SilentlyContinue)) { break }
                    Start-Sleep -Milliseconds 250
                }
                $msiArgs = @('/i', '%s', '/passive', '/norestart', '/l*v', '%s')
                $proc = Start-Process -FilePath 'msiexec.exe' -ArgumentList $msiArgs -Wait -PassThru
                if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 3010) {
                    $exe = '%s'
                    if ($exe -and (Test-Path $exe)) {
                        Start-Process -FilePath $exe
                    } else {
                        $fallback = Join-Path $env:LOCALAPPDATA 'Programs\\KILLAgent\\KILLAgent.exe'
                        if (Test-Path $fallback) { Start-Process -FilePath $fallback }
                    }
                }
                Remove-Item -LiteralPath $PSCommandPath -Force -ErrorAction SilentlyContinue
                """.formatted(pid, escapedMsi, escapedLog, escapedExe);

        Files.writeString(script, content, StandardCharsets.UTF_8);
        return script;
    }

    private static Path writePortableZipSwapScript(
            long pid,
            Path zipFile,
            Path installDir,
            Path exePath
    ) throws IOException {
        Path updatesDir = AppPaths.updatesDir();
        Files.createDirectories(updatesDir);
        Path script = updatesDir.resolve("apply-portable-update.ps1");

        String escapedZip = escapePsSingleQuote(zipFile.toAbsolutePath().toString());
        String escapedInstallDir = escapePsSingleQuote(installDir.toAbsolutePath().toString());
        String escapedExe = escapePsSingleQuote(exePath.toAbsolutePath().toString());
        String escapedStage = escapePsSingleQuote(updatesDir.resolve("stage-extract").toAbsolutePath().toString());

        String content = """
                $ErrorActionPreference = 'Stop'
                $targetPid = %d
                for ($i = 0; $i -lt 60; $i++) {
                    if (-not (Get-Process -Id $targetPid -ErrorAction SilentlyContinue)) { break }
                    Start-Sleep -Milliseconds 250
                }
                $stageDir = '%s'
                $installDir = '%s'
                $exePath = '%s'
                if (Test-Path $stageDir) { Remove-Item -Recurse -Force $stageDir }
                Expand-Archive -LiteralPath '%s' -DestinationPath $stageDir -Force
                $sourceRoot = $stageDir
                $nested = Join-Path $stageDir 'KILLAgent'
                if (Test-Path (Join-Path $nested 'KILLAgent.exe')) {
                    $sourceRoot = $nested
                }
                if (-not (Test-Path (Join-Path $sourceRoot 'KILLAgent.exe'))) {
                    throw "El paquete portátil verificado no contiene KILLAgent.exe"
                }
                Copy-Item -Path (Join-Path $sourceRoot '*') -Destination $installDir -Recurse -Force
                Remove-Item -Recurse -Force $stageDir -ErrorAction SilentlyContinue
                if (Test-Path $exePath) { Start-Process -FilePath $exePath }
                Remove-Item -LiteralPath $PSCommandPath -Force -ErrorAction SilentlyContinue
                """.formatted(pid, escapedStage, escapedInstallDir, escapedExe, escapedZip);

        Files.writeString(script, content, StandardCharsets.UTF_8);
        return script;
    }

    private static void launchDetachedPowerShell(Path scriptPath) throws IOException {
        new ProcessBuilder(
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-WindowStyle",
                "Hidden",
                "-File",
                scriptPath.toAbsolutePath().toString()
        ).start();
    }

    private static void openInExplorer(Path directory) {
        try {
            if (directory != null && Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.OPEN)) {
                Desktop.getDesktop().open(directory.toFile());
            }
        } catch (Exception e) {
            logger.debug("Could not open updates directory {}: {}", directory, e.getMessage());
        }
    }

    private static String escapePsSingleQuote(String input) {
        return input == null ? "" : input.replace("'", "''");
    }

    private static String sanitizeFileToken(String raw) {
        if (raw == null || raw.isBlank()) return "latest";
        return raw.replaceAll("[^0-9A-Za-z._-]", "_");
    }
}
