package pe.ong.chasca.killagent.config;

import io.github.cdimascio.dotenv.Dotenv;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.InputStream;
import java.net.InetAddress;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Loads and resolves KILLAgent configuration following strict priority order:
 * System Environment Variables -> .env file -> config.properties default fallback.
 */
public final class ConfigurationLoader {

    private static final Logger logger = LoggerFactory.getLogger(ConfigurationLoader.class);
    private static final String DEFAULT_PROPERTIES_PATH = "/config.properties";

    private ConfigurationLoader() {
        // Utility class
    }

    public static AgentConfig load() {
        Properties defaults = loadDefaultProperties();
        Dotenv dotenv = loadDotenv();

        String environment = resolve("ENVIRONMENT", dotenv, defaults, "development");
        int port = parsePort(resolve("KILLAGENT_PORT", dotenv, defaults, "3000"));
        String host = resolve("KILLAGENT_HOST", dotenv, defaults, "127.0.0.1");
        validateLoopbackHost(host);

        boolean secureWss = Boolean.parseBoolean(resolve("KILLAGENT_SECURE_WSS", dotenv, defaults, "false"));
        String keystorePath = resolve("KILLAGENT_KEYSTORE_PATH", dotenv, defaults, "./keystore/loopback.p12");
        String keystorePassword = resolveRaw("KILLAGENT_KEYSTORE_PASSWORD", dotenv, defaults, "changeit");

        String originsRaw = resolve("ALLOWED_ORIGINS", dotenv, defaults, "http://localhost:5173,http://localhost:8080");
        Set<String> allowedOrigins = Arrays.stream(originsRaw.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toCollection(LinkedHashSet::new));

        String dni2Dll = resolve("RENIEC_PKCS11_DLL_PATH_DNI2", dotenv, defaults, "C:\\Windows\\System32\\bit4ipki.dll");
        String dni3Dll = resolve("RENIEC_PKCS11_DLL_PATH_DNI3", dotenv, defaults, "C:\\Program Files\\IDEMIA\\IDPlugClassic\\DLLs\\idplug-pkcs11.dll");

        boolean isProd = "production".equalsIgnoreCase(environment);
        boolean mockHardware = !isProd && Boolean.parseBoolean(resolve("MOCK_HARDWARE_ENABLED", dotenv, defaults, "false"));
        String mockDni = resolve("MOCK_DNI_SIMULATED", dotenv, defaults, "71234567");
        String mockFullName = resolve("MOCK_USER_FULL_NAME", dotenv, defaults, "JUAN PEREZ GARCIA");
        String mockPin = resolve("MOCK_PIN", dotenv, defaults, "123456");

        String uiTheme = resolve("UI_THEME", dotenv, defaults, "auto");
        boolean showBalloons = Boolean.parseBoolean(resolve("SHOW_BALLOON_NOTIFICATIONS", dotenv, defaults, "true"));

        String digestModeStr = resolve("DOCUMENT_DIGEST_SIGN_MODE", dotenv, defaults, "PADES_DIGEST_INFO");
        AgentConfig.DocumentDigestSignMode digestMode = parseDigestMode(digestModeStr);

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
                mockHardware,
                mockDni,
                mockFullName,
                mockPin,
                uiTheme,
                showBalloons,
                digestMode
        );

        logger.info("Configuration loaded: env={}, endpoint={}://{}:{}, mockHardware={}, digestMode={}",
                config.environment(),
                config.secureWss() ? "wss" : "ws",
                config.host(),
                config.port(),
                config.mockHardwareEnabled(),
                config.documentDigestSignMode());
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

    private static int parsePort(String raw) {
        try {
            int p = Integer.parseInt(raw);
            if (p < 1 || p > 65535) {
                throw new IllegalArgumentException("Port out of valid TCP range: " + p);
            }
            return p;
        } catch (NumberFormatException e) {
            logger.warn("Invalid KILLAGENT_PORT '{}', falling back to 3000", raw);
            return 3000;
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

    private static String resolve(String key, Dotenv dotenv, Properties defaults, String fallback) {
        return stripInlineComment(resolveRaw(key, dotenv, defaults, fallback));
    }

    private static String resolveRaw(String key, Dotenv dotenv, Properties defaults, String fallback) {
        String val = System.getenv(key);
        if (val != null && !val.isBlank()) {
            return val.trim();
        }
        if (dotenv != null) {
            val = dotenv.get(key);
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

    private static Dotenv loadDotenv() {
        try {
            File envFile = new File(".env");
            if (envFile.exists()) {
                return Dotenv.configure()
                        .ignoreIfMissing()
                        .ignoreIfMalformed()
                        .load();
            }
        } catch (Exception e) {
            logger.warn("No .env file loaded: {}", e.getMessage());
        }
        return null;
    }
}
