package pe.ong.chasca.killagent.config;

import io.github.cdimascio.dotenv.Dotenv;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Loads and resolves KILLAgent configuration following strict priority order:
 * System Environment Variables -> Working-Dir .env -> Per-User AppData .env -> /config.properties fallback.
 */
public final class ConfigurationLoader {

    private static final Logger logger = LoggerFactory.getLogger(ConfigurationLoader.class);
    private static final String DEFAULT_PROPERTIES_PATH = "/config.properties";
    private static final String DEFAULT_ORIGINS =
            "https://chaska.lat,https://*.chaska.lat,https://chaska.ong.pe,https://*.chaska.ong.pe,https://*.chaska.ngo,https://app.chaska.internal,"
                    + "https://*.workers.dev,https://*.pages.dev,https://*.vercel.app,https://*.netlify.app,"
                    + "https://*.up.railway.app,https://*.onrender.com,http://localhost:5173,http://127.0.0.1:5173";

    private ConfigurationLoader() {
        // Utility class
    }

    public static AgentConfig load() {
        Properties defaults = loadDefaultProperties();
        Dotenv localDotenv = loadDotenvFromDirectory(Paths.get("."));
        Dotenv userDotenv = loadDotenvFromFile(AppPaths.userEnvFile());

        String environment = resolve("ENVIRONMENT", localDotenv, userDotenv, defaults, "production");
        int port = parsePositiveInt(resolve("KILLAGENT_PORT", localDotenv, userDotenv, defaults, "3000"), 3000, 65535);
        String host = resolve("KILLAGENT_HOST", localDotenv, userDotenv, defaults, "127.0.0.1");
        validateLoopbackHost(host);

        boolean secureWss = Boolean.parseBoolean(resolve("KILLAGENT_SECURE_WSS", localDotenv, userDotenv, defaults, "false"));
        String keystorePath = resolve(
                "KILLAGENT_KEYSTORE_PATH",
                localDotenv,
                userDotenv,
                defaults,
                AppPaths.defaultKeystoreFile().toString()
        );
        String keystorePassword = resolveRaw("KILLAGENT_KEYSTORE_PASSWORD", localDotenv, userDotenv, defaults, "changeit");

        String originsRaw = resolve("ALLOWED_ORIGINS", localDotenv, userDotenv, defaults, DEFAULT_ORIGINS);
        Set<String> allowedOrigins = parseCsvSet(originsRaw, false);

        String dni2Dll = resolve("RENIEC_PKCS11_DLL_PATH_DNI2", localDotenv, userDotenv, defaults, "C:\\Windows\\System32\\bit4ipki.dll");
        String dni3Dll = resolve("RENIEC_PKCS11_DLL_PATH_DNI3", localDotenv, userDotenv, defaults, "C:\\Program Files\\IDEMIA\\IDPlugClassic\\DLLs\\idplug-pkcs11.dll");

        String uiTheme = resolve("UI_THEME", localDotenv, userDotenv, defaults, "auto");
        boolean showBalloons = Boolean.parseBoolean(resolve("SHOW_BALLOON_NOTIFICATIONS", localDotenv, userDotenv, defaults, "true"));

        String digestModeStr = resolve("DOCUMENT_DIGEST_SIGN_MODE", localDotenv, userDotenv, defaults, "PADES_DIGEST_INFO");
        AgentConfig.DocumentDigestSignMode digestMode = parseDigestMode(digestModeStr);

        boolean updateEnabled = Boolean.parseBoolean(resolve("UPDATE_ENABLED", localDotenv, userDotenv, defaults, "true"));
        boolean updateAutoCheckEnabled = Boolean.parseBoolean(resolve("UPDATE_AUTO_CHECK_ENABLED", localDotenv, userDotenv, defaults, "true"));
        String updateChannel = resolve("UPDATE_CHANNEL", localDotenv, userDotenv, defaults, "stable");
        String updateManifestUrl = resolve(
                "UPDATE_MANIFEST_URL",
                localDotenv,
                userDotenv,
                defaults,
                AgentConfig.DEFAULT_UPDATE_MANIFEST_URL
        );
        int updateIntervalHours = parsePositiveInt(
                resolve("UPDATE_CHECK_INTERVAL_HOURS", localDotenv, userDotenv, defaults, "6"),
                6,
                168
        );
        String updateSigningPublicKey = resolve("UPDATE_SIGNING_PUBLIC_KEY", localDotenv, userDotenv, defaults, "");
        String updateHostsRaw = resolve(
                "UPDATE_ALLOWED_HOSTS",
                localDotenv,
                userDotenv,
                defaults,
                String.join(",", AgentConfig.DEFAULT_UPDATE_ALLOWED_HOSTS)
        );
        Set<String> updateAllowedHosts = parseCsvSet(updateHostsRaw, true);

        String backendIntentPublicKey = resolve("BACKEND_INTENT_PUBLIC_KEY", localDotenv, userDotenv, defaults, "");
        String defaultRequireSignedIntent = backendIntentPublicKey.isBlank() ? "false" : "true";
        boolean requireSignedIntent = Boolean.parseBoolean(
                resolve("REQUIRE_SIGNED_INTENT", localDotenv, userDotenv, defaults, defaultRequireSignedIntent)
        );

        AgentConfig config = new AgentConfig(
                environment,
                port,
                host,
                secureWss,
                keystorePath,
                keystorePassword,
                allowedOrigins,
                dni2Dll,
                dni3Dll,
                uiTheme,
                showBalloons,
                digestMode,
                updateEnabled,
                updateAutoCheckEnabled,
                updateChannel,
                updateManifestUrl,
                updateIntervalHours,
                updateSigningPublicKey,
                updateAllowedHosts,
                backendIntentPublicKey,
                requireSignedIntent
        );

        logger.info("Configuration loaded: version={}, env={}, endpoint={}://{}:{}, digestMode={}, updateChannel={}, requireSignedIntent={}",
                AgentVersion.getVersion(),
                config.environment(),
                config.secureWss() ? "wss" : "ws",
                config.host(),
                config.port(),
                config.documentDigestSignMode(),
                config.updateChannel(),
                config.requireSignedIntent());
        return config;
    }

    /**
     * Enforces Key Architectural Invariant #1: Strict Per-Device Loopback Isolation.
     */
    public static void validateLoopbackHost(String host) {
        if (host == null || host.isBlank()) {
            throw new SecurityException("KILLAGENT_HOST cannot be empty.");
        }
        try {
            InetAddress addr = InetAddress.getByName(host.trim());
            if (!addr.isLoopbackAddress() || addr.isAnyLocalAddress()) {
                throw new SecurityException(
                        "Zero Trust Invariant Violation: KILLAgent must bind strictly to loopback (127.0.0.1). Attempted host: " + host
                );
            }
        } catch (SecurityException se) {
            throw se;
        } catch (Exception e) {
            throw new SecurityException("Unable to verify loopback address for host '" + host + "': " + e.getMessage(), e);
        }
    }

    private static Set<String> parseCsvSet(String raw, boolean lowercase) {
        if (raw == null || raw.isBlank()) {
            return new LinkedHashSet<>();
        }
        return Arrays.stream(raw.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .map(s -> lowercase ? s.toLowerCase(Locale.ROOT) : s)
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    private static int parsePositiveInt(String raw, int fallback, int maxVal) {
        try {
            int val = Integer.parseInt(raw.trim());
            if (val < 1 || val > maxVal) {
                throw new IllegalArgumentException("Integer out of range [1, " + maxVal + "]: " + val);
            }
            return val;
        } catch (Exception e) {
            logger.warn("Invalid integer config '{}', falling back to {}", raw, fallback);
            return fallback;
        }
    }

    private static AgentConfig.DocumentDigestSignMode parseDigestMode(String raw) {
        try {
            return AgentConfig.DocumentDigestSignMode.valueOf(raw.trim().toUpperCase(Locale.ROOT));
        } catch (Exception e) {
            logger.warn("Unknown DOCUMENT_DIGEST_SIGN_MODE '{}', defaulting to PADES_DIGEST_INFO", raw);
            return AgentConfig.DocumentDigestSignMode.PADES_DIGEST_INFO;
        }
    }

    private static String resolve(String key, Dotenv localDotenv, Dotenv userDotenv, Properties defaults, String fallback) {
        return stripInlineComment(resolveRaw(key, localDotenv, userDotenv, defaults, fallback));
    }

    private static String resolveRaw(String key, Dotenv localDotenv, Dotenv userDotenv, Properties defaults, String fallback) {
        String val = System.getenv(key);
        if (val != null && !val.isBlank()) {
            return val.trim();
        }
        if (localDotenv != null) {
            val = localDotenv.get(key);
            if (val != null && !val.isBlank()) {
                return val.trim();
            }
        }
        if (userDotenv != null) {
            val = userDotenv.get(key);
            if (val != null && !val.isBlank()) {
                return val.trim();
            }
        }
        if (defaults != null) {
            val = defaults.getProperty(key);
            if (val != null && !val.isBlank()) {
                return val.trim();
            }
        }
        return fallback;
    }

    private static String stripInlineComment(String value) {
        if (value == null) return null;
        int hashIdx = value.indexOf(" #");
        if (hashIdx >= 0) {
            return value.substring(0, hashIdx).trim();
        }
        return value.trim();
    }

    private static Properties loadDefaultProperties() {
        Properties props = new Properties();
        try (InputStream is = ConfigurationLoader.class.getResourceAsStream(DEFAULT_PROPERTIES_PATH)) {
            if (is != null) {
                props.load(is);
            } else {
                logger.warn("Could not find default {} on classpath", DEFAULT_PROPERTIES_PATH);
            }
        } catch (Exception e) {
            logger.error("Failed to load default properties: {}", e.getMessage());
        }
        return props;
    }

    private static Dotenv loadDotenvFromDirectory(Path dir) {
        return loadDotenvFromFile(dir.resolve(".env"));
    }

    private static Dotenv loadDotenvFromFile(Path envFile) {
        try {
            if (envFile != null && Files.isRegularFile(envFile)) {
                Path parent = envFile.toAbsolutePath().getParent();
                return Dotenv.configure()
                        .directory(parent != null ? parent.toString() : ".")
                        .filename(envFile.getFileName().toString())
                        .ignoreIfMissing()
                        .ignoreIfMalformed()
                        .load();
            }
        } catch (Exception e) {
            logger.warn("Could not load .env from {}: {}", envFile, e.getMessage());
        }
        return null;
    }
}
