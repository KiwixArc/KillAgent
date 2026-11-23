package pe.ong.chasca.killagent.hardware.pkcs11;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pe.ong.chasca.killagent.config.AgentConfig;
import pe.ong.chasca.killagent.crypto.CertificatePurpose;
import pe.ong.chasca.killagent.crypto.CryptoOperationException;
import pe.ong.chasca.killagent.hardware.CardType;
import pe.ong.chasca.killagent.server.dto.ErrorCode;

import javax.security.auth.login.LoginException;
import java.io.File;
import java.security.AuthProvider;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Dynamic SunPKCS11 hardware bridge for RENIEC / IDEMIA DNIe cryptographic
 * middleware.
 * Manages lifecycle-scoped PKCS#11 sessions with deterministic C_Logout on
 * close
 * and safe multi-reader slot discovery that never double-submits an invalid
 * PIN.
 */
public class Pkcs11Bridge {

    private static final Logger logger = LoggerFactory.getLogger(Pkcs11Bridge.class);
    private static final int MAX_SLOT_SCAN_INDEX = 4;
    private static final Pattern FIR_SUBJECT_PATTERN = Pattern.compile("(?i).*\\b(FIR|FIRMA)\\b.*");

    private final AgentConfig config;
    private volatile Provider activeProvider;

    public Pkcs11Bridge(AgentConfig config) {
        this.config = config;
    }

    /**
     * Scoped PKCS#11 cryptographic session that automatically logs out of the
     * hardware token and unregisters the ephemeral provider upon completion.
     */
    public static final class Pkcs11Session implements AutoCloseable {
        private final Provider provider;
        private final KeyStore keyStore;
        private final Runnable closeAction;

        public Pkcs11Session(Provider provider, KeyStore keyStore, Runnable closeAction) {
            this.provider = provider;
            this.keyStore = keyStore;
            this.closeAction = closeAction;
        }

        public Provider provider() {
            return provider;
        }

        public KeyStore keyStore() {
            return keyStore;
        }

        @Override
        public void close() {
            if (closeAction != null) {
                closeAction.run();
            }
        }
    }

    /**
     * Resolves the installed PKCS#11 native DLL on Windows for the detected DNIe
     * generation.
     */
    public Optional<File> findPkcs11Library(CardType cardType) {
        Set<String> candidatePaths = new LinkedHashSet<>();

        if (cardType == CardType.DNIE_2_0) {
            candidatePaths.add(config.reniecPkcs11DllPathDni2());
        } else {
            candidatePaths.add(config.reniecPkcs11DllPathDni3());
        }

        // Standard IDEMIA IDPlugClassic (DNIe 3.0) & legacy RENIEC paths
        candidatePaths.add("C:\\Program Files\\IDEMIA\\IDPlugClassic\\DLLs\\idplug-pkcs11.dll");
        candidatePaths.add("C:\\Program Files (x86)\\IDEMIA\\IDPlugClassic\\DLLs\\idplug-pkcs11.dll");
        candidatePaths.add(config.reniecPkcs11DllPathDni3());
        candidatePaths.add(config.reniecPkcs11DllPathDni2());
        candidatePaths.add("C:\\Windows\\System32\\eps2003csp11.dll");
        candidatePaths.add("C:\\Windows\\SysWOW64\\eps2003csp11.dll");
        candidatePaths.add("C:\\Windows\\System32\\bit4ipki.dll");
        candidatePaths.add("C:\\Windows\\SysWOW64\\bit4ipki.dll");

        for (String rawPath : candidatePaths) {
            if (rawPath == null || rawPath.isBlank())
                continue;
            File f = new File(rawPath.trim());
            if (f.exists() && f.isFile()) {
                return Optional.of(f);
            }
        }
        return Optional.empty();
    }

    /**
     * Returns diagnostic list of all candidate PKCS#11 DLL paths and whether they
     * exist on disk.
     */
    public List<String> inspectInstalledDrivers() {
        List<String> report = new ArrayList<>();
        String[] paths = {
                config.reniecPkcs11DllPathDni3(),
                config.reniecPkcs11DllPathDni2(),
                "C:\\Program Files\\IDEMIA\\IDPlugClassic\\DLLs\\idplug-pkcs11.dll",
                "C:\\Windows\\System32\\eps2003csp11.dll",
                "C:\\Windows\\System32\\bit4ipki.dll"
        };
        Set<String> seen = new LinkedHashSet<>();
        for (String p : paths) {
            if (p == null || p.isBlank() || !seen.add(p))
                continue;
            File f = new File(p);
            report.add((f.exists() ? "[INSTALADO]  " : "[NO HALLADO] ") + p);
        }
        return report;
    }

    /**
     * Opens an authenticated, single-operation PKCS#11 session across available
     * reader slots.
     */
    public synchronized Pkcs11Session openSession(char[] pin, File libraryFile, Integer fallbackAttempts)
            throws CryptoOperationException {
        return openSession(pin, libraryFile, fallbackAttempts, CertificatePurpose.AUTHENTICATION);
    }

    /**
     * Opens an authenticated, single-operation PKCS#11 session across available
     * reader slots,
     * prioritizing slots that publicly expose a certificate matching
     * {@code purpose}
     * (e.g., Non-Repudiation / FIR for {@link CertificatePurpose#SIGNATURE}) before
     * performing C_Login.
     * Immediately halts slot scanning if a PIN error (CKR_PIN_INCORRECT /
     * CKR_PIN_LOCKED) occurs
     * so citizen PIN retry counters are never decremented more than once per
     * request.
     */
    public synchronized Pkcs11Session openSession(
            char[] pin,
            File libraryFile,
            Integer fallbackAttempts,
            CertificatePurpose purpose) throws CryptoOperationException {
        cleanup();

        CertificatePurpose effectivePurpose = purpose != null ? purpose : CertificatePurpose.AUTHENTICATION;
        List<Integer> candidateSlots = resolveSlotScanOrder(libraryFile, effectivePurpose);
        CryptoOperationException lastSlotError = null;

        for (int slotIndex : candidateSlots) {
            Provider slotProvider = null;
            try {
                slotProvider = configureSlotProvider(libraryFile, slotIndex);
                KeyStore keyStore = KeyStore.getInstance("PKCS11", slotProvider);
                keyStore.load(null, pin);

                final Provider loadedProvider = slotProvider;
                this.activeProvider = loadedProvider;
                logger.info("PKCS#11 session authenticated on slotListIndex={} (purpose={}) using {}",
                        slotIndex, effectivePurpose, libraryFile.getName());
                return new Pkcs11Session(loadedProvider, keyStore, () -> logoutAndUnload(loadedProvider));
            } catch (Throwable t) {
                logoutAndUnload(slotProvider);
                CryptoOperationException mapped = CryptoOperationException.fromPkcs11Exception(t, fallbackAttempts);

                // CRITICAL SAFETY: Never scan next slot if PIN was rejected or locked!
                if (mapped.getErrorCode() == ErrorCode.PIN_INCORRECT
                        || mapped.getErrorCode() == ErrorCode.PIN_LOCKED) {
                    throw mapped;
                }

                lastSlotError = mapped;
                logger.debug("Slot {} did not contain active DNIe token ({}). Trying next slot if available...",
                        slotIndex, mapped.getMessage());
            }
        }

        if (lastSlotError != null) {
            throw lastSlotError;
        }
        throw new CryptoOperationException(
                ErrorCode.CARD_NOT_PRESENT,
                "No se encontró un token DNIe válido en ninguna ranura PKCS#11.");
    }

    /**
     * Performs a read-only unauthenticated PKCS#11 public certificate inspection
     * across slots
     * (KeyStore.load(null, null) never invokes C_Login) so Non-Repudiation (FIR)
     * slots are
     * discovered and prioritized ahead of Authentication (AUT) slots when signing
     * documents.
     */
    private List<Integer> resolveSlotScanOrder(File libraryFile, CertificatePurpose purpose) {
        List<Integer> preferredSlots = new ArrayList<>();

        if (purpose == CertificatePurpose.SIGNATURE) {
            for (int slotIndex = 0; slotIndex < MAX_SLOT_SCAN_INDEX; slotIndex++) {
                Provider probeProvider = null;
                try {
                    probeProvider = configureSlotProvider(libraryFile, slotIndex);
                    KeyStore ks = KeyStore.getInstance("PKCS11", probeProvider);
                    ks.load(null, null);

                    Enumeration<String> aliases = ks.aliases();
                    while (aliases.hasMoreElements()) {
                        String alias = aliases.nextElement();
                        Certificate cert = ks.getCertificate(alias);
                        if (cert instanceof X509Certificate x509) {
                            boolean[] ku = x509.getKeyUsage();
                            boolean hasNonRepudiation = ku != null && ku.length > 1 && ku[1];
                            String subjectDn = x509.getSubjectX500Principal() != null
                                    ? x509.getSubjectX500Principal().getName()
                                    : "";
                            if (hasNonRepudiation || FIR_SUBJECT_PATTERN.matcher(subjectDn).matches()) {
                                preferredSlots.add(slotIndex);
                                logger.info(
                                        "Detected Non-Repudiation (FIR) certificate on slotListIndex={} [Subject={}]",
                                        slotIndex, subjectDn);
                                break;
                            }
                        }
                    }
                } catch (Exception ex) {
                    logger.debug("Unauthenticated public slot probe skipped slotListIndex={}: {}",
                            slotIndex, ex.getMessage());
                } finally {
                    logoutAndUnload(probeProvider);
                }
            }
        }

        LinkedHashSet<Integer> ordered = new LinkedHashSet<>(preferredSlots);
        for (int slotIndex = 0; slotIndex < MAX_SLOT_SCAN_INDEX; slotIndex++) {
            ordered.add(slotIndex);
        }
        return new ArrayList<>(ordered);
    }

    private Provider configureSlotProvider(File libraryFile, int slotListIndex) throws Exception {
        Provider baseProvider = Security.getProvider("SunPKCS11");
        if (baseProvider == null) {
            throw new IllegalStateException(
                    "El proveedor SunPKCS11 (jdk.crypto.cryptoki) no está disponible en el JRE.");
        }

        String uniqueSuffix = UUID.randomUUID().toString().substring(0, 8);
        String escapedPath = libraryFile.getAbsolutePath().replace("\\", "/");
        String inlineConfig = "--name = DNIe_" + slotListIndex + "_" + uniqueSuffix + "\n"
                + "library = \"" + escapedPath + "\"\n"
                + "slotListIndex = " + slotListIndex + "\n";

        Provider configured = baseProvider.configure(inlineConfig);
        Security.addProvider(configured);
        return configured;
    }

    private synchronized void logoutAndUnload(Provider provider) {
        if (provider == null)
            return;
        try {
            if (provider instanceof AuthProvider authProvider) {
                try {
                    authProvider.logout();
                    logger.debug("Executed PKCS#11 C_Logout on provider {}", provider.getName());
                } catch (LoginException le) {
                    logger.debug("PKCS#11 logout notice: {}", le.getMessage());
                }
            }
        } catch (Throwable t) {
            logger.debug("Error during PKCS#11 AuthProvider logout: {}", t.getMessage());
        } finally {
            try {
                Security.removeProvider(provider.getName());
            } catch (Throwable ignored) {
            }
            if (this.activeProvider == provider) {
                this.activeProvider = null;
            }
        }
    }

    /**
     * Immediately logs out and unloads any active SunPKCS11 provider (invoked on
     * Card Removal Kill-Switch & Shutdown).
     */
    public synchronized void cleanup() {
        if (activeProvider != null) {
            Provider p = activeProvider;
            activeProvider = null;
            logoutAndUnload(p);
            logger.info("Active SunPKCS11 cryptographic session invalidated and unloaded.");
        }
    }
}
