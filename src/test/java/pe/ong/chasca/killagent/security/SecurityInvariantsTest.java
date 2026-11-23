package pe.ong.chasca.killagent.security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import pe.ong.chasca.killagent.config.AgentConfig;
import pe.ong.chasca.killagent.config.ConfigurationLoader;

import javax.net.ssl.SSLContext;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class SecurityInvariantsTest {

    @Test
    void testOriginValidatorBlocksSubdomainSpoofingAndNullOrigins() {
        AgentConfig config = new AgentConfig(
                "production",
                3000,
                "127.0.0.1",
                false,
                "./keystore/loopback.p12",
                "changeit",
                Set.of("https://chaska.ong.pe", "http://localhost:5173"),
                "bit4ipki.dll",
                "idplug-pkcs11.dll",
                "auto",
                true
        );

        OriginValidator validator = new OriginValidator(config);

        // Legitimate origins (including case variations and default port 443)
        assertTrue(validator.isAllowed("https://chaska.ong.pe"));
        assertTrue(validator.isAllowed("HTTPS://CHASKA.ONG.PE:443"));
        assertTrue(validator.isAllowed("http://localhost:5173"));

        // Spoofing & attack vectors must be strictly rejected
        assertFalse(validator.isAllowed("https://chaska.ong.pe.evil.com"));
        assertFalse(validator.isAllowed("http://chaska.ong.pe")); // Downgrade HTTP instead of HTTPS
        assertFalse(validator.isAllowed("http://localhost:3000")); // Wrong port
        assertFalse(validator.isAllowed("null"));
        assertFalse(validator.isAllowed(""));
        assertFalse(validator.isAllowed(null));
    }

    @Test
    void testOriginValidatorSupportsHttpsDeploymentSubdomainWildcardsSafely() {
        AgentConfig config = new AgentConfig(
                "production",
                3000,
                "127.0.0.1",
                false,
                "./keystore/loopback.p12",
                "changeit",
                Set.of("https://*.pages.dev", "https://*.workers.dev", "https://*.chaska.ong.pe", "http://localhost:*"),
                "bit4ipki.dll",
                "idplug-pkcs11.dll",
                "auto",
                true
        );

        OriginValidator validator = new OriginValidator(config);

        assertTrue(validator.isAllowed("https://chaska-webapp.pages.dev"));
        assertTrue(validator.isAllowed("https://chaska-webapp.example.workers.dev"));
        assertTrue(validator.isAllowed("https://pr-42.chaska-webapp.pages.dev:443"));
        assertTrue(validator.isAllowed("https://app.chaska.ong.pe"));
        assertTrue(validator.isAllowed("http://localhost:5173"));
        assertTrue(validator.isAllowed("http://localhost:4173"));

        // Must reject insecure schemes, root suffixes without subdomain, and spoofed suffixes
        assertFalse(validator.isAllowed("http://chaska-webapp.pages.dev"));
        assertFalse(validator.isAllowed("https://pages.dev"));
        assertFalse(validator.isAllowed("https://chaska-webapp.pages.dev.evil.com"));
        assertFalse(validator.isAllowed("https://evil.com"));
    }

    @Test
    void testProductionRejectsWildcardOrigins() {
        assertThrows(SecurityException.class, () -> new AgentConfig(
                "production",
                3000,
                "127.0.0.1",
                false,
                "./ks.p12",
                "pw",
                Set.of("*"),
                "dni2.dll",
                "dni3.dll",
                "auto",
                false
        ));
    }

    @Test
    void testStrictLoopbackHostValidation() {
        assertDoesNotThrow(() -> ConfigurationLoader.validateLoopbackHost("127.0.0.1"));
        assertDoesNotThrow(() -> ConfigurationLoader.validateLoopbackHost("localhost"));

        // Binding to 0.0.0.0 or LAN interfaces must be blocked
        assertThrows(SecurityException.class, () -> ConfigurationLoader.validateLoopbackHost("0.0.0.0"));
        assertThrows(SecurityException.class, () -> ConfigurationLoader.validateLoopbackHost("::"));
    }

    @Test
    void testSingleInstanceLockExclusivity(@TempDir Path tempDir) {
        Path lockFile = tempDir.resolve("killagent.lock");

        try (SingleInstanceLock first = new SingleInstanceLock(lockFile);
             SingleInstanceLock second = new SingleInstanceLock(lockFile)) {
            assertTrue(first.tryAcquire(), "First daemon instance must acquire lock");
            assertFalse(second.tryAcquire(), "Second concurrent daemon instance must be blocked");
        }

        // After first closes, a new instance can acquire the lock
        try (SingleInstanceLock third = new SingleInstanceLock(lockFile)) {
            assertTrue(third.tryAcquire(), "Lock must be re-acquirable after clean shutdown");
        }
    }

    @Test
    void testLoopbackSslContextAutoProvisioningAndReload(@TempDir Path tempDir) throws Exception {
        Path p12Path = tempDir.resolve("keystore").resolve("loopback.p12");
        AgentConfig wssConfig = new AgentConfig(
                "development",
                3000,
                "127.0.0.1",
                true,
                p12Path.toString(),
                "test-secret-password",
                Set.of("http://localhost:5173"),
                "dni2.dll",
                "dni3.dll",
                "auto",
                false
        );

        // First call auto-provisions the PKCS#12 file
        SSLContext ctx1 = LoopbackSslContextFactory.createSslContext(wssConfig);
        assertNotNull(ctx1);
        assertTrue(Files.exists(p12Path));

        // Second call loads the existing PKCS#12 keystore from disk
        SSLContext ctx2 = LoopbackSslContextFactory.createSslContext(wssConfig);
        assertNotNull(ctx2);
    }
}
