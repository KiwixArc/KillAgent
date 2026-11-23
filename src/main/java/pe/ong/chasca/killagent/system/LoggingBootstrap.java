package pe.ong.chasca.killagent.system;

import pe.ong.chasca.killagent.config.AppPaths;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/**
 * Configures SLF4J Simple logging properties before the first Logger is initialized.
 * When launched as a packaged GUI desktop app (no attached console) or when
 * {@code KILLAGENT_LOG_TO_FILE=true}, logs are rotated and written to
 * {@code %LOCALAPPDATA%\Chaska\KILLAgent\logs\killagent.log}.
 */
public final class LoggingBootstrap {

    private static final long MAX_LOG_SIZE_BYTES = 5L * 1024L * 1024L;

    private LoggingBootstrap() {
    }

    public static void configure() {
        setPropertyIfAbsent("org.slf4j.simpleLogger.showDateTime", "true");
        setPropertyIfAbsent("org.slf4j.simpleLogger.dateTimeFormat", "yyyy-MM-dd HH:mm:ss.SSS");
        setPropertyIfAbsent("org.slf4j.simpleLogger.showThreadName", "true");
        setPropertyIfAbsent("org.slf4j.simpleLogger.levelInBrackets", "true");
        setPropertyIfAbsent("org.slf4j.simpleLogger.defaultLogLevel", "info");

        boolean forceFile = "true".equalsIgnoreCase(System.getenv("KILLAGENT_LOG_TO_FILE"));
        boolean noConsole = System.console() == null;

        if ((forceFile || noConsole) && System.getProperty("org.slf4j.simpleLogger.logFile") == null) {
            try {
                Path logsDir = AppPaths.logsDir();
                Files.createDirectories(logsDir);
                Path logFile = logsDir.resolve("killagent.log");

                if (Files.isRegularFile(logFile) && Files.size(logFile) > MAX_LOG_SIZE_BYTES) {
                    Path rotated = logsDir.resolve("killagent.log.1");
                    Files.move(logFile, rotated, StandardCopyOption.REPLACE_EXISTING);
                }

                System.setProperty("org.slf4j.simpleLogger.logFile", logFile.toAbsolutePath().toString());
            } catch (Exception ignored) {
                // Fall back to default stderr logging if AppData is temporarily unavailable
            }
        }
    }

    private static void setPropertyIfAbsent(String key, String value) {
        if (System.getProperty(key) == null) {
            System.setProperty(key, value);
        }
    }
}
