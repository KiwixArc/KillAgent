package pe.ong.chasca.killagent.security;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pe.ong.chasca.killagent.config.AgentConfig;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Date;

/**
 * Builds hardened TLSv1.3/TLSv1.2 SSLContext instances for wss://127.0.0.1 loopback transport.
 * Supports loading an existing PKCS#12 keystore or auto-provisioning a local loopback X.509 certificate
 * with SubjectAlternativeName (IP: 127.0.0.1, DNS: localhost) on first launch.
 */
public final class LoopbackSslContextFactory {

    private static final Logger logger = LoggerFactory.getLogger(LoopbackSslContextFactory.class);
    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final String ENTRY_ALIAS = "killagent-loopback";

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private LoopbackSslContextFactory() {}

    public static SSLContext createSslContext(AgentConfig config) throws Exception {
        Path ksPath = Paths.get(config.keystorePath());
        char[] password = config.keystorePassword() != null
                ? config.keystorePassword().toCharArray()
                : new char[0];

        try {
            KeyStore keyStore;
            if (Files.exists(ksPath)) {
                keyStore = loadExistingKeyStore(ksPath, password);
                logger.info("Loaded WSS TLS PKCS#12 keystore from: {}", ksPath.toAbsolutePath());
            } else {
                logger.info("WSS enabled and keystore not found at {}. Auto-provisioning loopback TLS certificate...", ksPath);
                keyStore = provisionLoopbackKeyStore(ksPath, password);
            }

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, password);

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(keyStore);

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
            return sslContext;
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static KeyStore loadExistingKeyStore(Path ksPath, char[] password) throws Exception {
        KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
        try (FileInputStream fis = new FileInputStream(ksPath.toFile())) {
            ks.load(fis, password);
        }
        return ks;
    }

    private static KeyStore provisionLoopbackKeyStore(Path ksPath, char[] password) throws Exception {
        Path parent = ksPath.getParent();
        if (parent != null && !Files.exists(parent)) {
            Files.createDirectories(parent);
        }

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048, new SecureRandom());
        KeyPair keyPair = kpg.generateKeyPair();

        Instant now = Instant.now();
        Date notBefore = Date.from(now.minus(1, ChronoUnit.HOURS));
        Date notAfter = Date.from(now.plus(825, ChronoUnit.DAYS)); // Browser max TLS validity window (~825 days)
        BigInteger serial = new BigInteger(128, new SecureRandom()).abs();

        X500Name dn = new X500Name("CN=127.0.0.1, OU=KILLAgent Loopback Anchor, O=Chasca Zero Trust, C=PE");

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                dn,
                serial,
                notBefore,
                notAfter,
                dn,
                keyPair.getPublic()
        );

        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));

        GeneralNames subjectAltNames = new GeneralNames(new GeneralName[]{
                new GeneralName(GeneralName.iPAddress, "127.0.0.1"),
                new GeneralName(GeneralName.dNSName, "localhost")
        });
        builder.addExtension(Extension.subjectAlternativeName, false, subjectAltNames);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
        X509CertificateHolder holder = builder.build(signer);
        X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(holder);

        KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
        ks.load(null, password);
        ks.setKeyEntry(ENTRY_ALIAS, keyPair.getPrivate(), password, new Certificate[]{certificate});

        try (FileOutputStream fos = new FileOutputStream(ksPath.toFile())) {
            ks.store(fos, password);
        }

        logger.info("Provisioned self-signed loopback TLS keystore at {}", ksPath.toAbsolutePath());
        return ks;
    }
}

