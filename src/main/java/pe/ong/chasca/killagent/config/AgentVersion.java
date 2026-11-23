package pe.ong.chasca.killagent.config;

import java.io.InputStream;
import java.util.Properties;

/**
 * Exposes the packaged KILLAgent application version and build timestamp.
 */
public final class AgentVersion {

    private static final String FALLBACK_VERSION = "1.0.0";
    private static final String VERSION_PROPERTIES_PATH = "/version.properties";

    private static final String VERSION;
    private static final String BUILD_TIMESTAMP;

    static {
        String resolvedVersion = null;
        String resolvedTimestamp = "";

        try (InputStream is = AgentVersion.class.getResourceAsStream(VERSION_PROPERTIES_PATH)) {
            if (is != null) {
                Properties props = new Properties();
                props.load(is);
                String rawVersion = props.getProperty("app.version", "").trim();
                if (!rawVersion.isEmpty() && !rawVersion.startsWith("${")) {
                    resolvedVersion = rawVersion;
                }
                String rawTimestamp = props.getProperty("app.build.timestamp", "").trim();
                if (!rawTimestamp.isEmpty() && !rawTimestamp.startsWith("${")) {
                    resolvedTimestamp = rawTimestamp;
                }
            }
        } catch (Exception ignored) {
        }

        if (resolvedVersion == null || resolvedVersion.isBlank()) {
            Package pkg = AgentVersion.class.getPackage();
            if (pkg != null && pkg.getImplementationVersion() != null && !pkg.getImplementationVersion().isBlank()) {
                resolvedVersion = pkg.getImplementationVersion().trim();
            }
        }

        VERSION = (resolvedVersion != null && !resolvedVersion.isBlank()) ? resolvedVersion : FALLBACK_VERSION;
        BUILD_TIMESTAMP = resolvedTimestamp;
    }

    private AgentVersion() {
    }

    public static String getVersion() {
        return VERSION;
    }

    public static String getCleanNumericVersion() {
        int dashIdx = VERSION.indexOf('-');
        return dashIdx > 0 ? VERSION.substring(0, dashIdx) : VERSION;
    }

    public static String getBuildTimestamp() {
        return BUILD_TIMESTAMP;
    }

    public static String getDisplayVersion() {
        return BUILD_TIMESTAMP.isBlank() ? "v" + VERSION : "v" + VERSION + " (" + BUILD_TIMESTAMP + ")";
    }
}
