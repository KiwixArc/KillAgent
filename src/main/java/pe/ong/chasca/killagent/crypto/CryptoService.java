package pe.ong.chasca.killagent.crypto;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pe.ong.chasca.killagent.config.AgentConfig;
import pe.ong.chasca.killagent.hardware.CardReaderManager;
import pe.ong.chasca.killagent.hardware.HardwareStatus;
import pe.ong.chasca.killagent.hardware.mock.MockHardwareService;
import pe.ong.chasca.killagent.hardware.pkcs11.Pkcs11Bridge;
import pe.ong.chasca.killagent.server.dto.ErrorCode;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

/**
 * Core Zero Trust cryptographic mediator coordinating physical RENIEC DNIe (PKCS#11)
 * and in-memory Sandbox operations with strict certificate KeyUsage enforcement,
 * RFC 8017 PAdES DigestInfo framing, and deterministic PIN memory zeroization.
 */
public class CryptoService {

    private static final Logger logger = LoggerFactory.getLogger(CryptoService.class);
    private static final Pattern FIR_SUBJECT_PATTERN = Pattern.compile("(?i).*\\b(FIR|FIRMA)\\b.*");

    private final AgentConfig config;
    private final CardReaderManager cardReaderManager;
    private final Pkcs11Bridge pkcs11Bridge;
    private final MockHardwareService mockHardwareService;
    private final AtomicInteger hardwarePinAttemptEstimator = new AtomicInteger(3);

    public CryptoService(
            AgentConfig config,
            CardReaderManager cardReaderManager,
            Pkcs11Bridge pkcs11Bridge,
            MockHardwareService mockHardwareService
    ) {
        this.config = config;
        this.cardReaderManager = cardReaderManager;
        this.pkcs11Bridge = pkcs11Bridge;
        this.mockHardwareService = mockHardwareService;
    }

    /**
     * Resets the estimated hardware PIN attempt counter (e.g., when a new card is inserted).
     */
    public void resetEstimatedPinAttempts() {
        hardwarePinAttemptEstimator.set(3);
    }

    /**
     * Signs an authentication challenge nonce using the DNIe Authentication certificate
     * (KeyUsage: Digital Signature without Non-Repudiation).
     */
    public AuthChallengeResult signAuthChallenge(char[] rawPin, String nonce) throws CryptoOperationException {
        try (PinBuffer safePin = PinBuffer.adopt(rawPin)) {
            ensureCardPresent();
            validatePinNonEmpty(safePin);
            byte[] challengeBytes = RsaDigestInfoHelper.decodeChallengeNonce(nonce);

            if (cardReaderManager.isMockActive()) {
                mockHardwareService.authenticatePinOrThrow(safePin.getPin());
                try {
                    X509Certificate cert = mockHardwareService.getAuthCertificate();
                    verifyCertificateValidity(cert);
                    String signedNonce = mockHardwareService.signDataWithAuthKey(challengeBytes);
                    String pem = MockHardwareService.convertToPem(cert);
                    Map<String, String> meta = extractCertificateMetadata(cert);
                    enrichWithHardwareMetadata(meta);
                    cardReaderManager.updateDetectedCardholderIdentity(meta.get("dni"), meta.get("fullName"));
                    return new AuthChallengeResult(nonce.trim(), signedNonce, pem, meta);
                } catch (CryptoOperationException coe) {
                    throw coe;
                } catch (Exception e) {
                    throw new CryptoOperationException(ErrorCode.PKCS11_ERROR, "Error en firma Sandbox: " + e.getMessage(), null, e);
                }
            }

            // Physical PKCS#11 Hardware Execution
            File dllFile = resolvePkcs11DriverOrThrow();
            int nextEstimatedOnFailure = Math.max(0, hardwarePinAttemptEstimator.get() - 1);

            try (Pkcs11Bridge.Pkcs11Session session = pkcs11Bridge.openSession(
                    safePin.getPin(), dllFile, nextEstimatedOnFailure, CertificatePurpose.AUTHENTICATION)) {
                hardwarePinAttemptEstimator.set(3); // Successful login resets retry counter on DNIe chip

                KeyStore ks = session.keyStore();
                String authAlias = selectCertificateAlias(ks, CertificatePurpose.AUTHENTICATION);

                X509Certificate cert = (X509Certificate) ks.getCertificate(authAlias);
                verifyCertificateValidity(cert);

                PrivateKey privateKey = (PrivateKey) ks.getKey(authAlias, null);
                Signature sig = Signature.getInstance("SHA256withRSA", session.provider());
                sig.initSign(privateKey);
                sig.update(challengeBytes);
                byte[] signatureBytes = sig.sign();

                String signedB64 = Base64.getEncoder().encodeToString(signatureBytes);
                String pem = MockHardwareService.convertToPem(cert);
                Map<String, String> meta = extractCertificateMetadata(cert);
                enrichWithHardwareMetadata(meta);
                cardReaderManager.updateDetectedCardholderIdentity(meta.get("dni"), meta.get("fullName"));

                logger.info("Authentication challenge signed via physical DNIe (alias={}, reader={}, serial={})",
                        authAlias, meta.get("readerName"), meta.get("certificateSerialNumber"));
                return new AuthChallengeResult(nonce.trim(), signedB64, pem, meta);
            } catch (CryptoOperationException coe) {
                if (coe.getErrorCode() == ErrorCode.PIN_INCORRECT) {
                    hardwarePinAttemptEstimator.set(nextEstimatedOnFailure);
                } else if (coe.getErrorCode() == ErrorCode.PIN_LOCKED) {
                    hardwarePinAttemptEstimator.set(0);
                }
                throw coe;
            } catch (Exception e) {
                throw CryptoOperationException.fromPkcs11Exception(e, null);
            }
        } finally {
            if (rawPin != null) {
                Arrays.fill(rawPin, '\0');
            }
        }
    }

    /**
     * Signs a 32-byte SHA-256 document digest for PAdES-LTV digital signatures using
     * strictly the DNIe Non-Repudiation / Content Commitment certificate.
     */
    public DocumentDigestResult signDocumentDigest(char[] rawPin, String slotId, String documentHashHex)
            throws CryptoOperationException {
        try (PinBuffer safePin = PinBuffer.adopt(rawPin)) {
            ensureCardPresent();
            validatePinNonEmpty(safePin);

            if (slotId == null || slotId.isBlank()) {
                throw new CryptoOperationException(ErrorCode.MALFORMED_REQUEST, "El identificador de firma (slotId) es obligatorio.");
            }

            byte[] rawSha256Bytes = RsaDigestInfoHelper.decodeSha256Hex(documentHashHex);
            String cleanHashHex = documentHashHex.trim();

            // Prepare signing input and JCA algorithm according to configured PAdES digest mode
            final byte[] payloadToSign;
            final String jcaAlgorithm;
            switch (config.documentDigestSignMode()) {
                case PADES_DIGEST_INFO -> {
                    payloadToSign = RsaDigestInfoHelper.buildSha256DigestInfo(rawSha256Bytes);
                    jcaAlgorithm = "NONEwithRSA";
                }
                case SHA256_OVER_HASH_BYTES -> {
                    payloadToSign = rawSha256Bytes;
                    jcaAlgorithm = "SHA256withRSA";
                }
                case SHA256_OVER_HEX_STRING -> {
                    payloadToSign = cleanHashHex.getBytes(StandardCharsets.UTF_8);
                    jcaAlgorithm = "SHA256withRSA";
                }
                default -> throw new IllegalStateException("Unhandled digest mode: " + config.documentDigestSignMode());
            }

            if (cardReaderManager.isMockActive()) {
                mockHardwareService.authenticatePinOrThrow(safePin.getPin());
                try {
                    X509Certificate cert = mockHardwareService.getSignCertificate();
                    verifyCertificateValidity(cert);

                    String signatureValue = mockHardwareService.signDataWithSignKey(payloadToSign, jcaAlgorithm);
                    String pem = MockHardwareService.convertToPem(cert);
                    Map<String, String> meta = extractCertificateMetadata(cert);
                    cardReaderManager.updateDetectedCardholderIdentity(meta.get("dni"), meta.get("fullName"));

                    return new DocumentDigestResult(
                            slotId.trim(),
                            meta.getOrDefault("dni", config.mockDniSimulated()),
                            cleanHashHex,
                            signatureValue,
                            formatCanonicalReniecDn(cert),
                            meta.get("certificateSerialNumber"),
                            pem
                    );
                } catch (CryptoOperationException coe) {
                    throw coe;
                } catch (Exception e) {
                    throw new CryptoOperationException(ErrorCode.PKCS11_ERROR, "Error en firma PAdES Sandbox: " + e.getMessage(), null, e);
                }
            }

            // Physical PKCS#11 Hardware Execution
            File dllFile = resolvePkcs11DriverOrThrow();
            int nextEstimatedOnFailure = Math.max(0, hardwarePinAttemptEstimator.get() - 1);

            try (Pkcs11Bridge.Pkcs11Session session = pkcs11Bridge.openSession(
                    safePin.getPin(), dllFile, nextEstimatedOnFailure, CertificatePurpose.SIGNATURE)) {
                hardwarePinAttemptEstimator.set(3);

                KeyStore ks = session.keyStore();
                String signAlias = selectCertificateAlias(ks, CertificatePurpose.SIGNATURE);

                X509Certificate cert = (X509Certificate) ks.getCertificate(signAlias);
                verifyCertificateValidity(cert);

                PrivateKey privateKey = (PrivateKey) ks.getKey(signAlias, null);
                byte[] signatureBytes;
                try {
                    Signature sig = Signature.getInstance(jcaAlgorithm, session.provider());
                    sig.initSign(privateKey);
                    sig.update(payloadToSign);
                    signatureBytes = sig.sign();
                } catch (Exception primaryEx) {
                    if (!"NONEwithRSA".equalsIgnoreCase(jcaAlgorithm)) {
                        throw primaryEx;
                    }
                    logger.warn("PKCS#11 NONEwithRSA failed on alias={}, falling back to SHA256withRSA over hash bytes: {}",
                            signAlias, primaryEx.getMessage());
                    Signature fallbackSig = Signature.getInstance("SHA256withRSA", session.provider());
                    fallbackSig.initSign(privateKey);
                    fallbackSig.update(rawSha256Bytes);
                    signatureBytes = fallbackSig.sign();
                }

                String signatureValue = Base64.getEncoder().encodeToString(signatureBytes);
                String pem = MockHardwareService.convertToPem(cert);
                Map<String, String> meta = extractCertificateMetadata(cert);
                cardReaderManager.updateDetectedCardholderIdentity(meta.get("dni"), meta.get("fullName"));

                logger.info("Document digest signed via physical DNIe Non-Repudiation key (alias={}, slotId={})",
                        signAlias, slotId);

                return new DocumentDigestResult(
                        slotId.trim(),
                        meta.getOrDefault("dni", "UNKNOWN"),
                        cleanHashHex,
                        signatureValue,
                        formatCanonicalReniecDn(cert),
                        meta.get("certificateSerialNumber"),
                        pem
                );
            } catch (CryptoOperationException coe) {
                if (coe.getErrorCode() == ErrorCode.PIN_INCORRECT) {
                    hardwarePinAttemptEstimator.set(nextEstimatedOnFailure);
                } else if (coe.getErrorCode() == ErrorCode.PIN_LOCKED) {
                    hardwarePinAttemptEstimator.set(0);
                }
                throw coe;
            } catch (Exception e) {
                throw CryptoOperationException.fromPkcs11Exception(e, null);
            }
        } finally {
            if (rawPin != null) {
                Arrays.fill(rawPin, '\0');
            }
        }
    }

    private void ensureCardPresent() throws CryptoOperationException {
        HardwareStatus status = cardReaderManager.getStatus();
        if (!status.readerPresent()) {
            throw new CryptoOperationException(
                    ErrorCode.CARD_NOT_PRESENT,
                    "No se detectó ningún lector de tarjetas inteligentes conectado a la estación de trabajo."
            );
        }
        if (!status.cardPresent()) {
            throw new CryptoOperationException(
                    ErrorCode.CARD_NOT_PRESENT,
                    "Inserte su DNI Electrónico (DNIe) en el lector para continuar."
            );
        }
    }

    private void validatePinNonEmpty(PinBuffer safePin) throws CryptoOperationException {
        if (safePin.length() < 4) {
            throw new CryptoOperationException(
                    ErrorCode.PIN_INCORRECT,
                    "El PIN del DNIe debe contener al menos 4 dígitos."
            );
        }
    }

    private File resolvePkcs11DriverOrThrow() throws CryptoOperationException {
        HardwareStatus status = cardReaderManager.getStatus();
        return pkcs11Bridge.findPkcs11Library(status.cardType())
                .orElseThrow(() -> new CryptoOperationException(
                        ErrorCode.PKCS11_ERROR,
                        "No se encontró el driver PKCS#11 de RENIEC/IDEMIA (" + config.reniecPkcs11DllPathDni3() + "). Instale IDPlugClassic."
                ));
    }

    /**
     * Differentiates between DNIe Authentication and Non-Repudiation Digital Signature certificates.
     * Prefers Non-Repudiation / Content Commitment for SIGNATURE; if the active hardware slot only
     * exposes an active DigitalSignature key entry (e.g., IDPlugClassic slot 0), falls back to it cleanly.
     */
    String selectCertificateAlias(KeyStore ks, CertificatePurpose purpose) throws Exception {
        String secondaryAuthCandidate = null;
        String firSubjectCandidate = null;
        String secondarySignatureCandidate = null;
        Enumeration<String> aliases = ks.aliases();

        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (!ks.isKeyEntry(alias)) {
                continue;
            }
            java.security.cert.Certificate rawCert = ks.getCertificate(alias);
            if (!(rawCert instanceof X509Certificate cert)) {
                continue;
            }

            boolean[] keyUsage = cert.getKeyUsage();
            // X.509 KeyUsage bits: [0] = digitalSignature, [1] = nonRepudiation (contentCommitment)
            boolean hasDigitalSignature = keyUsage != null && keyUsage.length > 0 && keyUsage[0];
            boolean hasNonRepudiation = keyUsage != null && keyUsage.length > 1 && keyUsage[1];
            String subjectDn = cert.getSubjectX500Principal() != null ? cert.getSubjectX500Principal().getName() : "";

            if (purpose == CertificatePurpose.SIGNATURE) {
                if (hasNonRepudiation) {
                    logger.info("Selected Non-Repudiation (keyUsage[1]=true) DNIe certificate alias '{}' [Subject={}]",
                            alias, subjectDn);
                    return alias;
                }
                if (FIR_SUBJECT_PATTERN.matcher(subjectDn).matches() && firSubjectCandidate == null) {
                    firSubjectCandidate = alias;
                } else if ((hasDigitalSignature || keyUsage == null) && secondarySignatureCandidate == null) {
                    secondarySignatureCandidate = alias;
                }
            } else if (purpose == CertificatePurpose.AUTHENTICATION) {
                if (hasDigitalSignature && !hasNonRepudiation) {
                    return alias;
                }
                if (hasDigitalSignature && secondaryAuthCandidate == null) {
                    secondaryAuthCandidate = alias;
                }
            }
        }

        if (purpose == CertificatePurpose.SIGNATURE) {
            if (firSubjectCandidate != null) {
                logger.info("Selected DNIe FIR subject certificate alias '{}' for signing.", firSubjectCandidate);
                return firSubjectCandidate;
            }
            if (secondarySignatureCandidate != null) {
                logger.warn("No dedicated FIR (Non-Repudiation) certificate exposed on active PKCS#11 slot; using fallback hardware certificate alias '{}' for signing.",
                        secondarySignatureCandidate);
                return secondarySignatureCandidate;
            }
        }

        if (purpose == CertificatePurpose.AUTHENTICATION && secondaryAuthCandidate != null) {
            return secondaryAuthCandidate;
        }

        String missingType = (purpose == CertificatePurpose.SIGNATURE)
                ? "Firma Digital (No Repudio / Content Commitment)"
                : "Autenticación Digital";
        throw new CryptoOperationException(
                ErrorCode.PKCS11_ERROR,
                "El DNIe insertado no contiene un certificado activo habilitado para " + missingType + "."
        );
    }

    private void verifyCertificateValidity(X509Certificate cert) throws CryptoOperationException {
        try {
            cert.checkValidity();
        } catch (CertificateExpiredException e) {
            throw new CryptoOperationException(
                    ErrorCode.CERTIFICATE_EXPIRED,
                    "Los certificados digitales de su DNIe han expirado (" + cert.getNotAfter() + "). Renuévelos en RENIEC.",
                    null,
                    e
            );
        } catch (CertificateNotYetValidException e) {
            throw new CryptoOperationException(
                    ErrorCode.CERTIFICATE_EXPIRED,
                    "El certificado digital del DNIe aún no entra en vigencia.",
                    null,
                    e
            );
        }
    }

    /**
     * Extracts canonical citizen metadata from a RENIEC X.509 certificate.
     */
    public static Map<String, String> extractCertificateMetadata(X509Certificate cert) {
        Map<String, String> map = new LinkedHashMap<>();

        String dni = "";
        String fullName = "";

        try {
            JcaX509CertificateHolder holder = new JcaX509CertificateHolder(cert);
            X500Name subject = holder.getSubject();

            fullName = firstRdnString(subject, BCStyle.CN);
            String rawSn = firstRdnString(subject, BCStyle.SERIALNUMBER);
            if (!rawSn.isEmpty()) {
                // RENIEC serial numbers follow patterns such as "DNI71234567" or "PNOPE-71234567"
                String digitsOnly = rawSn.replaceAll("[^0-9]", "");
                dni = digitsOnly.length() >= 8 ? digitsOnly.substring(0, 8) : digitsOnly;
            }
        } catch (Exception e) {
            logger.warn("Could not extract X.509 metadata via Bouncy Castle holder: {}", e.getMessage());
        }

        map.put("dni", dni);
        map.put("fullName", fullName);
        map.put("certificateSerialNumber", cert.getSerialNumber().toString(16).toUpperCase(Locale.ROOT));
        map.put("validTo", DateTimeFormatter.ISO_INSTANT.format(cert.getNotAfter().toInstant()));
        return map;
    }

    private void enrichWithHardwareMetadata(Map<String, String> meta) {
        HardwareStatus currentStatus = cardReaderManager.getStatus();
        String readerName = currentStatus.readerName() != null && !currentStatus.readerName().isBlank()
                ? currentStatus.readerName().trim()
                : "PC/SC SmartCard Reader";
        String cardType = currentStatus.cardType() != null
                ? currentStatus.cardType().name()
                : "DNIE_3_0";
        String atr = cardReaderManager.getLastDetectedAtrHex() != null
                ? cardReaderManager.getLastDetectedAtrHex()
                : "";
        meta.put("readerName", readerName);
        meta.put("cardType", cardType);
        meta.put("cardAtr", atr);
    }

    /**
     * Formats the certificate Subject DN matching the canonical RENIEC convention:
     * "CN=JUAN PEREZ GARCIA, SERIALNUMBER=DNI71234567, O=RENIEC, C=PE"
     */
    public static String formatCanonicalReniecDn(X509Certificate cert) {
        try {
            JcaX509CertificateHolder holder = new JcaX509CertificateHolder(cert);
            X500Name subject = holder.getSubject();

            List<String> parts = new ArrayList<>();
            String cn = firstRdnString(subject, BCStyle.CN);
            String sn = firstRdnString(subject, BCStyle.SERIALNUMBER);
            String org = firstRdnString(subject, BCStyle.O);
            String country = firstRdnString(subject, BCStyle.C);

            if (!cn.isEmpty()) parts.add("CN=" + cn);
            if (!sn.isEmpty()) parts.add("SERIALNUMBER=" + sn);
            if (!org.isEmpty()) parts.add("O=" + org);
            if (!country.isEmpty()) parts.add("C=" + country);

            if (!parts.isEmpty()) {
                return String.join(", ", parts);
            }
        } catch (Exception ignored) {
        }
        return cert.getSubjectX500Principal().getName();
    }

    private static String firstRdnString(X500Name name, org.bouncycastle.asn1.ASN1ObjectIdentifier oid) {
        RDN[] rdns = name.getRDNs(oid);
        if (rdns != null && rdns.length > 0 && rdns[0].getFirst() != null) {
            return IETFUtils.valueToString(rdns[0].getFirst().getValue()).trim();
        }
        return "";
    }
}
