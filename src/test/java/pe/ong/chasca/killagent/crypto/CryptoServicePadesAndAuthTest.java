package pe.ong.chasca.killagent.crypto;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import pe.ong.chasca.killagent.config.AgentConfig;
import pe.ong.chasca.killagent.hardware.CardReaderManager;
import pe.ong.chasca.killagent.server.dto.ErrorCode;
import pe.ong.chasca.killagent.testsupport.MutableTestHardwareProbe;
import pe.ong.chasca.killagent.testsupport.TestSoftTokenPkcs11Bridge;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.HexFormat;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class CryptoServicePadesAndAuthTest {

    private MutableTestHardwareProbe hardwareProbe;
    private CardReaderManager readerManager;
    private TestSoftTokenPkcs11Bridge pkcs11Bridge;
    private CryptoService cryptoService;

    @BeforeEach
    void setUp() {
        AgentConfig config = new AgentConfig(
                "development",
                3000,
                "127.0.0.1",
                false,
                "./keystore/loopback.p12",
                "changeit",
                Set.of("http://localhost:5173"),
                "bit4ipki.dll",
                "idplug-pkcs11.dll",
                "auto",
                false
        );
        hardwareProbe = new MutableTestHardwareProbe(true);
        readerManager = new CardReaderManager(config, hardwareProbe);
        readerManager.probeOnce(false);
        pkcs11Bridge = new TestSoftTokenPkcs11Bridge(config, "71234567", "JUAN PEREZ GARCIA");
        cryptoService = new CryptoService(config, readerManager, pkcs11Bridge);
    }

    @Test
    void testPadesDocumentDigestSignatureVerifiesAgainstOriginalPdfBytes() throws Exception {
        // Simulate a real PDF document's TBS (To-Be-Signed) byte stream
        byte[] simulatedPdfBytes = "%PDF-1.7 Convenio de Cooperacion Tecnica Chaska 2026...".getBytes(StandardCharsets.UTF_8);
        byte[] sha256Bytes = MessageDigest.getInstance("SHA-256").digest(simulatedPdfBytes);
        String sha256Hex = HexFormat.of().formatHex(sha256Bytes);

        char[] pin = new char[]{'1', '2', '3', '4', '5', '6'};
        DocumentDigestResult result = cryptoService.signDocumentDigest(
                pin,
                "b18f8101-5e92-4293-8b7c-7a54911f32a0",
                sha256Hex
        );

        // 1. Memory Invariant: Raw PIN char[] must be completely zeroed out in-place
        for (char c : pin) {
            assertEquals('\0', c, "PIN character buffer must be wiped to '\\0' immediately after signing");
        }

        // 2. Contract fields verification
        assertEquals("71234567", result.certificateDni());
        assertEquals("CN=JUAN PEREZ GARCIA, SERIALNUMBER=DNI71234567, O=RENIEC, C=PE", result.signerSubjectDn());

        // 3. Parse returned PEM certificate and verify Non-Repudiation KeyUsage
        X509Certificate returnedCert = parsePemCertificate(result.clientCertificatePem());
        assertTrue(returnedCert.getKeyUsage()[1], "PAdES signature certificate MUST carry Non-Repudiation KeyUsage");

        // 4. Mathematical Proof: Verify signature directly against ORIGINAL PDF bytes using standard SHA256withRSA!
        Signature pdfVerifier = Signature.getInstance("SHA256withRSA");
        pdfVerifier.initVerify(returnedCert.getPublicKey());
        pdfVerifier.update(simulatedPdfBytes);
        assertTrue(
                pdfVerifier.verify(Base64.getDecoder().decode(result.signatureValue())),
                "DigestInfo + NONEwithRSA signature must verify identically to SHA256withRSA over original PDF!"
        );
    }

    @Test
    void testAuthChallengeUsesAuthenticationCertAndZeroesPin() throws Exception {
        String nonceHex = "a4f891e204b7c9103f8a12d4e567890123456789abcdef0123456789abcdef01";
        char[] pin = new char[]{'6', '5', '4', '3', '2', '1'};

        AuthChallengeResult result = cryptoService.signAuthChallenge(pin, nonceHex);

        for (char c : pin) {
            assertEquals('\0', c, "PIN array must be zeroed after authentication signing");
        }

        X509Certificate authCert = parsePemCertificate(result.clientCertificatePem());
        assertTrue(authCert.getKeyUsage()[0], "Auth cert must have DigitalSignature KeyUsage");
        assertFalse(authCert.getKeyUsage()[1], "Auth cert must NOT have Non-Repudiation KeyUsage");

        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(authCert.getPublicKey());
        verifier.update(HexFormat.of().parseHex(nonceHex));
        assertTrue(verifier.verify(Base64.getDecoder().decode(result.signedNonce())));

        assertNotNull(result.metadata().get("readerName"));
        assertFalse(result.metadata().get("readerName").isBlank());
        assertEquals("DNIE_3_0", result.metadata().get("cardType"));
    }

    @Test
    void testThreeStrikePinLockoutAndCardNotPresent() {
        // Strike 1 -> 2 attempts left
        CryptoOperationException ex1 = assertThrows(CryptoOperationException.class,
                () -> cryptoService.signAuthChallenge(new char[]{'0', '0', '0', '0'}, "a4f891e204b7c9103f8a12d4e5678901"));
        assertEquals(ErrorCode.PIN_INCORRECT, ex1.getErrorCode());
        assertEquals(2, ex1.getAttemptsRemaining());

        // Strike 2 -> 1 attempt left
        CryptoOperationException ex2 = assertThrows(CryptoOperationException.class,
                () -> cryptoService.signAuthChallenge(new char[]{'0', '0', '0', '0'}, "a4f891e204b7c9103f8a12d4e5678901"));
        assertEquals(ErrorCode.PIN_INCORRECT, ex2.getErrorCode());
        assertEquals(1, ex2.getAttemptsRemaining());

        // Strike 3 -> 0 attempts left (PIN_LOCKED)
        CryptoOperationException ex3 = assertThrows(CryptoOperationException.class,
                () -> cryptoService.signAuthChallenge(new char[]{'0', '0', '0', '0'}, "a4f891e204b7c9103f8a12d4e5678901"));
        assertEquals(ErrorCode.PIN_LOCKED, ex3.getErrorCode());
        assertEquals(0, ex3.getAttemptsRemaining());

        // Reset PIN counter, remove card, verify CARD_NOT_PRESENT
        pkcs11Bridge.resetPinAttempts();
        hardwareProbe.removeCard();
        readerManager.probeOnce(true);

        CryptoOperationException exRemoved = assertThrows(CryptoOperationException.class,
                () -> cryptoService.signAuthChallenge(new char[]{'1', '2', '3', '4'}, "a4f891e204b7c9103f8a12d4e5678901"));
        assertEquals(ErrorCode.CARD_NOT_PRESENT, exRemoved.getErrorCode());
    }

    @Test
    void testSelectCertificateAliasPrefersNonRepudiationAndFallsBackToDigitalSignature() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);

        KeyPair authKp = kpg.generateKeyPair();
        X509Certificate authOnlyCert = createSelfSignedCert(authKp, new KeyUsage(KeyUsage.digitalSignature));

        // 1. Slot exposes only DigitalSignature certificate -> falls back cleanly for SIGNATURE
        KeyStore authOnlyKs = KeyStore.getInstance("PKCS12");
        authOnlyKs.load(null, null);
        authOnlyKs.setKeyEntry("auth-slot0", authKp.getPrivate(), null, new Certificate[]{authOnlyCert});

        assertEquals("auth-slot0", cryptoService.selectCertificateAlias(authOnlyKs, CertificatePurpose.SIGNATURE));

        // 2. Slot exposes both DigitalSignature and Non-Repudiation -> strictly prefers Non-Repudiation
        KeyPair signKp = kpg.generateKeyPair();
        X509Certificate nonRepudiationCert = createSelfSignedCert(
                signKp,
                new KeyUsage(KeyUsage.nonRepudiation | KeyUsage.digitalSignature)
        );
        KeyStore dualKs = KeyStore.getInstance("PKCS12");
        dualKs.load(null, null);
        dualKs.setKeyEntry("auth-slot0", authKp.getPrivate(), null, new Certificate[]{authOnlyCert});
        dualKs.setKeyEntry("sign-slot0", signKp.getPrivate(), null, new Certificate[]{nonRepudiationCert});

        assertEquals("sign-slot0", cryptoService.selectCertificateAlias(dualKs, CertificatePurpose.SIGNATURE));

        // 3. Slot exposes AUT and FIR-labeled cert (without keyUsage bit 1) -> prefers FIR subject over AUT
        KeyPair firLabelKp = kpg.generateKeyPair();
        X509Certificate firLabelCert = createSelfSignedCertWithSubject(
                firLabelKp,
                "CN=CERVANTES RODRIGUEZ Freddy Hector FIR 23837036 hard, SERIALNUMBER=PNOPE-23837036, C=PE",
                new KeyUsage(KeyUsage.digitalSignature)
        );
        KeyStore firSubjectKs = KeyStore.getInstance("PKCS12");
        firSubjectKs.load(null, null);
        firSubjectKs.setKeyEntry("auth-slot0", authKp.getPrivate(), null, new Certificate[]{authOnlyCert});
        firSubjectKs.setKeyEntry("fir-label-slot1", firLabelKp.getPrivate(), null, new Certificate[]{firLabelCert});

        assertEquals("fir-label-slot1", cryptoService.selectCertificateAlias(firSubjectKs, CertificatePurpose.SIGNATURE));
    }

    private static X509Certificate createSelfSignedCert(KeyPair kp, KeyUsage keyUsage) throws Exception {
        return createSelfSignedCertWithSubject(kp, "CN=TEST USER, SERIALNUMBER=DNI23837036, O=RENIEC, C=PE", keyUsage);
    }

    private static X509Certificate createSelfSignedCertWithSubject(KeyPair kp, String subjectDn, KeyUsage keyUsage) throws Exception {
        long now = System.currentTimeMillis();
        X500Name name = new X500Name(subjectDn);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name,
                BigInteger.valueOf(now),
                new Date(now - 60_000L),
                new Date(now + 86_400_000L),
                name,
                kp.getPublic()
        );
        builder.addExtension(Extension.keyUsage, true, keyUsage);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(kp.getPrivate());
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));
    }

    private static X509Certificate parsePemCertificate(String pem) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8))
        );
    }
}

