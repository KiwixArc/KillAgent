package pe.ong.chasca.killagent.hardware.mock;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pe.ong.chasca.killagent.config.AgentConfig;
import pe.ong.chasca.killagent.crypto.CryptoOperationException;
import pe.ong.chasca.killagent.server.dto.ErrorCode;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * In-memory Bouncy Castle hardware simulator for local development and testing without physical DNIe cards.
 * Emulates dual RENIEC X.509 certificates (Authentication & Non-Repudiation Digital Signature),
 * memory-safe PIN verification (zero String allocations), and realistic 3-strike PIN lockout behavior.
 */
public class MockHardwareService {

    private static final Logger logger = LoggerFactory.getLogger(MockHardwareService.class);
    private static final int MAX_PIN_ATTEMPTS = 3;

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final AgentConfig config;
    private final AtomicInteger remainingAttempts = new AtomicInteger(MAX_PIN_ATTEMPTS);

    private KeyPair authKeyPair;
    private X509Certificate authCertificate;
    private KeyPair signKeyPair;
    private X509Certificate signCertificate;

    public MockHardwareService(AgentConfig config) {
        this.config = config;
        initializeMockKeys();
    }

    private void initializeMockKeys() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
            kpg.initialize(2048, new SecureRandom());

            this.authKeyPair = kpg.generateKeyPair();
            this.signKeyPair = kpg.generateKeyPair();

            String dni = config.mockDniSimulated();
            String name = config.mockUserFullName();

            X500NameBuilder subjectBuilder = new X500NameBuilder(BCStyle.INSTANCE);
            subjectBuilder.addRDN(BCStyle.CN, name);
            subjectBuilder.addRDN(BCStyle.SERIALNUMBER, "DNI" + dni);
            subjectBuilder.addRDN(BCStyle.O, "RENIEC");
            subjectBuilder.addRDN(BCStyle.C, "PE");
            X500Name subject = subjectBuilder.build();

            this.authCertificate = generateCertificate(
                    authKeyPair,
                    subject,
                    new KeyUsage(KeyUsage.digitalSignature)
            );
            this.signCertificate = generateCertificate(
                    signKeyPair,
                    subject,
                    new KeyUsage(KeyUsage.nonRepudiation | KeyUsage.digitalSignature)
            );

            logger.info("Mock DNIe 3.0 RSA-2048 keys and RENIEC certificates initialized for DNI: {}", dni);
        } catch (Exception e) {
            logger.error("Failed to generate mock cryptographic credentials: {}", e.getMessage(), e);
            throw new IllegalStateException("Mock crypto initialization failed", e);
        }
    }

    private X509Certificate generateCertificate(KeyPair keyPair, X500Name subject, KeyUsage keyUsage) throws Exception {
        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 1000L * 60 * 60 * 24);
        Date notAfter = new Date(now + 1000L * 60 * 60 * 24 * 365 * 2); // 2 years validity
        BigInteger serial = new BigInteger(64, new SecureRandom()).abs();

        X500NameBuilder issuerBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        issuerBuilder.addRDN(BCStyle.CN, "RENIEC CA CLASE 1 - SUBCA ENTIDAD CERTIFICADORA DEL ESTADO PERUANO");
        issuerBuilder.addRDN(BCStyle.O, "RENIEC");
        issuerBuilder.addRDN(BCStyle.C, "PE");
        X500Name issuer = issuerBuilder.build();

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                serial,
                notBefore,
                notAfter,
                subject,
                keyPair.getPublic()
        );

        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        certBuilder.addExtension(Extension.keyUsage, true, keyUsage);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC")
                .build(keyPair.getPrivate());
        X509CertificateHolder holder = certBuilder.build(signer);

        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
    }

    /**
     * Validates a PIN strictly over char[] without creating any immutable java.lang.String on the heap.
     * Note: Entering all-zeros ('0000' / '000000') deliberately triggers a simulated wrong-PIN failure
     * so developers can test PIN_INCORRECT and PIN_LOCKED UI workflows end-to-end.
     */
    public boolean validatePin(char[] pin) {
        if (pin == null || pin.length < 4 || pin.length > 8) {
            return false;
        }
        boolean allZeros = true;
        for (char c : pin) {
            if (c < '0' || c > '9') {
                return false;
            }
            if (c != '0') {
                allZeros = false;
            }
        }
        return !allZeros;
    }

    /**
     * Authenticates a Sandbox PIN operation enforcing the 3-attempt hardware lockout counter.
     */
    public synchronized void authenticatePinOrThrow(char[] pin) throws CryptoOperationException {
        if (remainingAttempts.get() <= 0) {
            throw new CryptoOperationException(
                    ErrorCode.PIN_LOCKED,
                    "El PIN del DNIe (Sandbox) se encuentra bloqueado tras 3 intentos fallidos.",
                    0
            );
        }

        if (!validatePin(pin)) {
            int left = Math.max(0, remainingAttempts.decrementAndGet());
            if (left == 0) {
                throw new CryptoOperationException(
                        ErrorCode.PIN_LOCKED,
                        "El PIN del DNIe se ha bloqueado tras agotar los intentos permitidos.",
                        0
                );
            }
            throw new CryptoOperationException(
                    ErrorCode.PIN_INCORRECT,
                    "El PIN ingresado es incorrecto. Quedan " + left + " intentos restantes.",
                    left
            );
        }

        // Valid PIN resets the hardware retry counter to 3
        remainingAttempts.set(MAX_PIN_ATTEMPTS);
    }

    public void resetPinAttempts() {
        remainingAttempts.set(MAX_PIN_ATTEMPTS);
        logger.info("[Sandbox] Mock DNIe PIN retry counter reset to {}.", MAX_PIN_ATTEMPTS);
    }

    public int getRemainingAttempts() {
        return remainingAttempts.get();
    }

    public String signDataWithAuthKey(byte[] data) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA", "BC");
        signature.initSign(authKeyPair.getPrivate());
        signature.update(data);
        return Base64.getEncoder().encodeToString(signature.sign());
    }

    public String signDataWithSignKey(byte[] data, String jcaAlgorithm) throws Exception {
        Signature signature = Signature.getInstance(jcaAlgorithm, "BC");
        signature.initSign(signKeyPair.getPrivate());
        signature.update(data);
        return Base64.getEncoder().encodeToString(signature.sign());
    }

    public X509Certificate getAuthCertificate() {
        return authCertificate;
    }

    public X509Certificate getSignCertificate() {
        return signCertificate;
    }

    public static String convertToPem(X509Certificate certificate) {
        try {
            String b64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(certificate.getEncoded());
            return "-----BEGIN CERTIFICATE-----\n" + b64 + "\n-----END CERTIFICATE-----";
        } catch (Exception e) {
            throw new IllegalStateException("Error encoding X.509 certificate to PEM", e);
        }
    }
}
