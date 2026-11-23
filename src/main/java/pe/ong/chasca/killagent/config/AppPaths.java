package pe.ong.chasca.killagent.config;

import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Resolves writable per-user OS directories for KILLAgent runtime state,
 * configuration overrides, lock files, logs, TLS keystores, and verified update payloads.
 */
public final class AppPaths {

    private static final String VENDOR_DIR = "Chaska";
    private static final String APP_DIR = "KILLAgent";

    private AppPaths() {
    }

    public static Path baseDataDir() {
        String customHome = System.getenv("KILLAGENT_HOME");
        if (customHome != null && !customHome.isBlank()) {
            return Paths.get(customHome.trim());
        }
        String localAppData = System.getenv("LOCALAPPDATA");
        if (localAppData != null && !localAppData.isBlank()) {
            return Paths.get(localAppData, VENDOR_DIR, APP_DIR);
        }
        return Paths.get(System.getProperty("java.io.tmpdir"), "chaska-killagent");
    }

    public static Path userEnvFile() {
        return baseDataDir().resolve(".env");
    }

    public static Path defaultKeystoreFile() {
        return baseDataDir().resolve("keystore").resolve("loopback.p12");
    }

    public static Path lockFile() {
        String customHome = System.getenv("KILLAGENT_HOME");
        if (customHome != null && !customHome.isBlank()) {
            return Paths.get(customHome.trim(), "killagent.lock");
        }
        String localAppData = System.getenv("LOCALAPPDATA");
        if (localAppData != null && !localAppData.isBlank()) {
            return Paths.get(localAppData, VENDOR_DIR, APP_DIR, "killagent.lock");
        }
        return Paths.get(System.getProperty("java.io.tmpdir"), "chaska-killagent.lock");
    }

    public static Path logsDir() {
        return baseDataDir().resolve("logs");
    }

    public static Path updatesDir() {
        return baseDataDir().resolve("updates");
    }
}
