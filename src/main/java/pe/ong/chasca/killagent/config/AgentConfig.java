package pe.ong.chasca.killagent.config;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

/**
 * Immutable runtime configuration holder for KILLAgent.
 * Enforces Zero Trust architectural invariants at construction time.
 */
public record AgentConfig(
        String environment,
        int port,
        String host,
        boolean secureWss,
        String keystorePath,
        String keystorePassword,
        Set<String> allowedOrigins,
        String reniecPkcs11DllPathDni2,
        String reniecPkcs11DllPathDni3,
        boolean mockHardwareEnabled,
        String mockDniSimulated,
        String mockUserFullName,
        String mockPin,
        String uiTheme,
        boolean showBalloonNotifications,
        DocumentDigestSignMode documentDigestSignMode
) {
    /**
     * Defines how the 32-byte SHA-256 documentHash is signed by the RSA private key.
     */
    public enum DocumentDigestSignMode {
        /**
         * Wraps the 32-byte SHA-256 hash into an RFC 8017 ASN.1 DigestInfo structure
         * and signs with NONEwithRSA (CKM_RSA_PKCS). Produces a signature mathematically
         * identical to SHA256withRSA over the original PDF document bytes (PAdES standard).
         */
        PADES_DIGEST_INFO,

        /**
         * Signs the raw decoded bytes of the hex hash using SHA256withRSA.
         */
        SHA256_OVER_HASH_BYTES,

        /**
         * Signs the UTF-8 string representation of the hex hash using SHA256withRSA.
         */
        SHA256_OVER_HEX_STRING
    }

    public AgentConfig {
        Objects.requireNonNull(environment, "environment must not be null");
        Objects.requireNonNull(host, "host must not be null");
        Objects.requireNonNull(allowedOrigins, "allowedOrigins must not be null");

        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("Invalid port number: " + port);
        }

        boolean isProd = "production".equalsIgnoreCase(environment.trim());
        if (isProd && allowedOrigins.contains("*")) {
            throw new SecurityException("Zero Trust violation: wildcard '*' is strictly forbidden in ALLOWED_ORIGINS in production.");
        }

        if (isProd && mockHardwareEnabled) {
            throw new SecurityException("Zero Trust violation: MOCK_HARDWARE_ENABLED cannot be active in production environment.");
        }

        allowedOrigins = Collections.unmodifiableSet(new LinkedHashSet<>(allowedOrigins));
        if (mockPin == null || mockPin.isBlank()) {
            mockPin = "123456";
        }
        if (documentDigestSignMode == null) {
            documentDigestSignMode = DocumentDigestSignMode.PADES_DIGEST_INFO;
        }
    }

    /**
     * Convenience constructor with default mock PIN and standard PAdES digest mode.
     */
    public AgentConfig(
            String environment,
            int port,
            String host,
            boolean secureWss,
            String keystorePath,
            String keystorePassword,
            Set<String> allowedOrigins,
            String reniecPkcs11DllPathDni2,
            String reniecPkcs11DllPathDni3,
            boolean mockHardwareEnabled,
            String mockDniSimulated,
            String mockUserFullName,
            String uiTheme,
            boolean showBalloonNotifications
    ) {
        this(
                environment,
                port,
                host,
                secureWss,
                keystorePath,
                keystorePassword,
                allowedOrigins,
                reniecPkcs11DllPathDni2,
                reniecPkcs11DllPathDni3,
                mockHardwareEnabled,
                mockDniSimulated,
                mockUserFullName,
                "123456",
                uiTheme,
                showBalloonNotifications,
                DocumentDigestSignMode.PADES_DIGEST_INFO
        );
    }

    public boolean isDevelopment() {
        return "development".equalsIgnoreCase(environment);
    }

    public boolean isProduction() {
        return "production".equalsIgnoreCase(environment);
    }
}
