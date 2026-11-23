package pe.ong.chasca.killagent.testsupport;

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
import pe.ong.chasca.killagent.config.AgentConfig;
import pe.ong.chasca.killagent.crypto.CertificatePurpose;
import pe.ong.chasca.killagent.crypto.CryptoOperationException;
import pe.ong.chasca.killagent.hardware.CardType;
import pe.ong.chasca.killagent.hardware.pkcs11.Pkcs11Bridge;
import pe.ong.chasca.killagent.server.dto.ErrorCode;

import java.io.File;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Test-only Pkcs11Bridge backed by ephemeral in-memory RSA-2048 Bouncy Castle credentials
 * with separate Authentication (DigitalSignature) and Signature (Non-Repudiation) certificates
 * and 3-strike PIN lockout simulation (rejects non-digit/short or all-zero PINs).
 */
public final class TestSoftTokenPkcs11Bridge extends Pkcs11Bridge {

    private static final int MAX_PIN_ATTEMPTS = 3;

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final AtomicInteger remainingAttempts = new AtomicInteger(MAX_PIN_ATTEMPTS);
    private final KeyStore keyStore;
    private final X509Certificate authCertificate;
    private final X509Certificate signCertificate;

    public TestSoftTokenPkcs11Bridge(AgentConfig config, String dni, String fullName) {
        super(config);
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
            kpg.initialize(2048, new SecureRandom());

            KeyPair authKp = kpg.generateKeyPair();
            KeyPair signKp = kpg.generateKeyPair();

            X500NameBuilder subjectBuilder = new X500NameBuilder(BCStyle.INSTANCE);
            subjectBuilder.addRDN(BCStyle.CN, fullName);
            subjectBuilder.addRDN(BCStyle.SERIALNUMBER, "DNI" + dni);
            subjectBuilder.addRDN(BCStyle.O, "RENIEC");
            subjectBuilder.addRDN(BCStyle.C, "PE");
            X500Name subject = subjectBuilder.build();

            this.authCertificate = buildCert(authKp, subject, new KeyUsage(KeyUsage.digitalSignature));
            this.signCertificate = buildCert(signKp, subject, new KeyUsage(KeyUsage.nonRepudiation | KeyUsage.digitalSignature));

            this.keyStore = KeyStore.getInstance("PKCS12");
            this.keyStore.load(null, null);
            this.keyStore.setKeyEntry("auth-slot0", authKp.getPrivate(), null, new Certificate[]{authCertificate});
            this.keyStore.setKeyEntry("sign-slot0", signKp.getPrivate(), null, new Certificate[]{signCertificate});
        } catch (Exception e) {
            throw new IllegalStateException("Failed to initialize test soft token bridge", e);
        }
    }

    private static X509Certificate buildCert(KeyPair kp, X500Name subject, KeyUsage keyUsage) throws Exception {
        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 60_000L);
        Date notAfter = new Date(now + 86_400_000L * 365L);
        BigInteger serial = new BigInteger(64, new SecureRandom()).abs();

        X500NameBuilder issuerBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        issuerBuilder.addRDN(BCStyle.CN, "RENIEC TEST CA");
        issuerBuilder.addRDN(BCStyle.O, "RENIEC");
        issuerBuilder.addRDN(BCStyle.C, "PE");

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuerBuilder.build(),
                serial,
                notBefore,
                notAfter,
                subject,
                kp.getPublic()
        );
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.keyUsage, true, keyUsage);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(kp.getPrivate());
        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
    }

    @Override
    public Optional<File> findPkcs11Library(CardType cardType) {
        return Optional.of(new File("virtual-test-pkcs11.dll"));
    }

    @Override
    public synchronized Pkcs11Session openSession(
            char[] pin,
            File libraryFile,
            Integer fallbackAttempts,
            CertificatePurpose purpose
    ) throws CryptoOperationException {
        if (remainingAttempts.get() <= 0) {
            throw new CryptoOperationException(
                    ErrorCode.PIN_LOCKED,
                    "El PIN del DNIe se encuentra bloqueado tras 3 intentos fallidos.",
                    0
            );
        }
        if (!isPinValid(pin)) {
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
        remainingAttempts.set(MAX_PIN_ATTEMPTS);
        return new Pkcs11Session(null, keyStore, () -> {});
    }

    public void resetPinAttempts() {
        remainingAttempts.set(MAX_PIN_ATTEMPTS);
    }

    public X509Certificate getAuthCertificate() {
        return authCertificate;
    }

    public X509Certificate getSignCertificate() {
        return signCertificate;
    }

    private static boolean isPinValid(char[] pin) {
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
}
