package pe.ong.chasca.killagent.hardware.mock;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import pe.ong.chasca.killagent.config.AgentConfig;

import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class MockHardwareServiceTest {

    private MockHardwareService mockHardwareService;

    @BeforeEach
    void setUp() {
        AgentConfig config = new AgentConfig(
                "development",
                3000,
                "127.0.0.1",
                false,
                "./keystore.p12",
                "secret",
                Set.of("http://localhost:5173"),
                "bit4ipki.dll",
                "eps2003csp11.dll",
                true,
                "71234567",
                "JUAN PEREZ GARCIA",
                "auto",
                true
        );
        mockHardwareService = new MockHardwareService(config);
    }

    @Test
    void testCertificatesGenerated() {
        X509Certificate authCert = mockHardwareService.getAuthCertificate();
        X509Certificate signCert = mockHardwareService.getSignCertificate();

        assertNotNull(authCert);
        assertNotNull(signCert);

        var authMeta = pe.ong.chasca.killagent.crypto.CryptoService.extractCertificateMetadata(authCert);
        assertEquals("71234567", authMeta.get("dni"));
        assertEquals("JUAN PEREZ GARCIA", authMeta.get("fullName"));

        // Key usage verification
        assertNotNull(authCert.getKeyUsage());
        assertTrue(authCert.getKeyUsage()[0]); // digitalSignature
        assertFalse(authCert.getKeyUsage()[1]); // nonRepudiation is false for auth

        assertTrue(signCert.getKeyUsage()[1]); // nonRepudiation is true for sign
    }

    @Test
    void testAuthSignatureMathValidity() throws Exception {
        byte[] nonce = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8);
        String signatureB64 = mockHardwareService.signDataWithAuthKey(nonce);

        assertNotNull(signatureB64);
        byte[] sigBytes = Base64.getDecoder().decode(signatureB64);

        // Verify with public key from X.509 cert
        Signature verifier = Signature.getInstance("SHA256withRSA", "BC");
        verifier.initVerify(mockHardwareService.getAuthCertificate().getPublicKey());
        verifier.update(nonce);
        assertTrue(verifier.verify(sigBytes));
    }

    @Test
    void testPinValidation() {
        assertTrue(mockHardwareService.validatePin(new char[]{'1', '2', '3', '4'}));
        assertTrue(mockHardwareService.validatePin(new char[]{'1', '2', '3', '4', '5', '6'}));
        assertFalse(mockHardwareService.validatePin(new char[]{'1', '2'}));
        assertFalse(mockHardwareService.validatePin(new char[]{'a', 'b', 'c', 'd'}));
    }
}
