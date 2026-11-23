package pe.ong.chasca.killagent.system;

import com.sun.jna.platform.win32.Advapi32Util;
import com.sun.jna.platform.win32.WinReg;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pe.ong.chasca.killagent.KillAgentApplication;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Locale;
import java.util.Optional;

/**
 * Manages per-user Windows auto-start registration via HKCU Run registry key.
 */
public final class WindowsStartupManager {

    private static final Logger logger = LoggerFactory.getLogger(WindowsStartupManager.class);
    private static final String RUN_REGISTRY_PATH = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    private static final String ENTRY_NAME = "KILLAgent";

    private WindowsStartupManager() {
    }

    public static boolean isSupported() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
    }

    public static boolean isAutoStartEnabled() {
        if (!isSupported()) {
            return false;
        }
        try {
            return Advapi32Util.registryValueExists(WinReg.HKEY_CURRENT_USER, RUN_REGISTRY_PATH, ENTRY_NAME);
        } catch (Throwable t) {
            logger.debug("Could not inspect Windows Run registry entry: {}", t.getMessage());
            return false;
        }
    }

    public static boolean setAutoStartEnabled(boolean enabled) {
        if (!isSupported()) {
            return false;
        }
        try {
            if (enabled) {
                Optional<String> cmdOpt = resolveStartupCommand();
                if (cmdOpt.isEmpty()) {
                    logger.warn("Could not determine standalone KILLAgent executable or JAR path for auto-start.");
                    return false;
                }
                Advapi32Util.registrySetStringValue(
                        WinReg.HKEY_CURRENT_USER,
                        RUN_REGISTRY_PATH,
                        ENTRY_NAME,
                        cmdOpt.get()
                );
                logger.info("Registered KILLAgent Windows auto-start command: {}", cmdOpt.get());
                return true;
            } else {
                if (Advapi32Util.registryValueExists(WinReg.HKEY_CURRENT_USER, RUN_REGISTRY_PATH, ENTRY_NAME)) {
                    Advapi32Util.registryDeleteValue(WinReg.HKEY_CURRENT_USER, RUN_REGISTRY_PATH, ENTRY_NAME);
                    logger.info("Removed KILLAgent Windows auto-start registry entry.");
                }
                return true;
            }
        } catch (Throwable t) {
            logger.warn("Failed to update Windows auto-start registry setting: {}", t.getMessage());
            return false;
        }
    }

    public static Optional<String> resolveStartupCommand() {
        Optional<String> cmdOpt = ProcessHandle.current().info().command();
        if (cmdOpt.isPresent()) {
            String cmd = cmdOpt.get().trim();
            if (cmd.toLowerCase(Locale.ROOT).endsWith("killagent.exe") && Files.isRegularFile(Paths.get(cmd))) {
                return Optional.of("\"" + cmd + "\"");
            }
        }

        try {
            var codeSource = KillAgentApplication.class.getProtectionDomain().getCodeSource();
            if (codeSource != null && codeSource.getLocation() != null) {
                URI location = codeSource.getLocation().toURI();
                Path jarPath = Paths.get(location);
                if (Files.isRegularFile(jarPath) && jarPath.toString().toLowerCase(Locale.ROOT).endsWith(".jar")) {
                    String javaw = resolveJavawExecutable();
                    return Optional.of("\"" + javaw + "\" -jar \"" + jarPath.toAbsolutePath() + "\"");
                }
            }
        } catch (Exception e) {
            logger.debug("Could not resolve code source JAR path: {}", e.getMessage());
        }
        return Optional.empty();
    }

    private static String resolveJavawExecutable() {
        String javaHome = System.getProperty("java.home");
        if (javaHome != null && !javaHome.isBlank()) {
            Path javaw = Paths.get(javaHome, "bin", "javaw.exe");
            if (Files.isRegularFile(javaw)) {
                return javaw.toAbsolutePath().toString();
            }
            Path java = Paths.get(javaHome, "bin", "java.exe");
            if (Files.isRegularFile(java)) {
                return java.toAbsolutePath().toString();
            }
        }
        return "javaw.exe";
    }
}
