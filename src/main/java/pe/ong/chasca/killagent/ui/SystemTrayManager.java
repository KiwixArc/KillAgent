package pe.ong.chasca.killagent.ui;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pe.ong.chasca.killagent.config.AgentConfig;
import pe.ong.chasca.killagent.crypto.AuthChallengeResult;
import pe.ong.chasca.killagent.crypto.CryptoService;
import pe.ong.chasca.killagent.hardware.CardReaderManager;
import pe.ong.chasca.killagent.hardware.CardType;
import pe.ong.chasca.killagent.hardware.HardwareListener;
import pe.ong.chasca.killagent.hardware.HardwareStatus;
import pe.ong.chasca.killagent.hardware.mock.MockHardwareService;
import pe.ong.chasca.killagent.hardware.pkcs11.Pkcs11Bridge;

import javax.swing.*;
import java.awt.*;
import java.util.function.IntSupplier;

/**
 * Manages Windows 11 Taskbar System Tray presence, dynamic SVG state icon rendering,
 * masked cardholder identity status pill, and contextual operational actions.
 */
public class SystemTrayManager implements HardwareListener {

    private static final Logger logger = LoggerFactory.getLogger(SystemTrayManager.class);
    private static final String TEST_CHALLENGE_NONCE =
            "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

    private final AgentConfig config;
    private final CardReaderManager readerManager;
    private final Pkcs11Bridge pkcs11Bridge;
    private final MockHardwareService mockHardwareService;
    private final CryptoService cryptoService;
    private final PinPromptProvider pinPromptProvider;
    private final Runnable restartServerAction;
    private final Runnable exitAction;

    private volatile IntSupplier activeConnectionsSupplier = () -> 0;
    private volatile boolean busySigning = false;

    private TrayIcon trayIcon;
    private MenuItem statusHeaderItem;
    private MenuItem readerDetailItem;
    private MenuItem toggleSandboxItem;
    private MenuItem simulateCardToggleItem;
    private DiagnosticsDialog diagnosticsDialog;

    public SystemTrayManager(
            AgentConfig config,
            CardReaderManager readerManager,
            Pkcs11Bridge pkcs11Bridge,
            MockHardwareService mockHardwareService,
            CryptoService cryptoService,
            PinPromptProvider pinPromptProvider,
            Runnable restartServerAction,
            Runnable exitAction
    ) {
        this.config = config;
        this.readerManager = readerManager;
        this.pkcs11Bridge = pkcs11Bridge;
        this.mockHardwareService = mockHardwareService;
        this.cryptoService = cryptoService;
        this.pinPromptProvider = pinPromptProvider;
        this.restartServerAction = restartServerAction;
        this.exitAction = exitAction;

        readerManager.addListener(this);
    }

    public void setActiveConnectionsSupplier(IntSupplier supplier) {
        if (supplier != null) {
            this.activeConnectionsSupplier = supplier;
        }
    }

    public void initialize() {
        if (GraphicsEnvironment.isHeadless() || !SystemTray.isSupported()) {
            logger.warn("SystemTray is not supported on this workstation environment.");
            return;
        }

        try {
            SystemTray tray = SystemTray.getSystemTray();
            PopupMenu popup = createPopupMenu();

            Image initialImage = AssetManager.getTrayIcon(determineCurrentState());
            trayIcon = new TrayIcon(initialImage, "KILLAgent — Ch'asca Zero Trust Anchor", popup);
            trayIcon.setImageAutoSize(true);
            trayIcon.addActionListener(e -> openDiagnostics()); // Double-click opens Diagnostics

            tray.add(trayIcon);
            updateStatusDisplay();
            logger.info("Windows SystemTray icon registered.");
        } catch (Exception e) {
            logger.error("Failed to initialize SystemTray: {}", e.getMessage(), e);
        }
    }

    public void shutdown() {
        if (trayIcon != null && SystemTray.isSupported()) {
            try {
                SystemTray.getSystemTray().remove(trayIcon);
            } catch (Exception ignored) {
            }
            trayIcon = null;
        }
        if (diagnosticsDialog != null) {
            SwingUtilities.invokeLater(() -> diagnosticsDialog.dispose());
        }
    }

    private PopupMenu createPopupMenu() {
        PopupMenu popup = new PopupMenu();

        // 1. Header / Status Pill (Connection state + Masked DNI + Reader Model)
        statusHeaderItem = new MenuItem("KILLAgent: Inicializando...");
        statusHeaderItem.setEnabled(false);
        popup.add(statusHeaderItem);

        readerDetailItem = new MenuItem("Lector: Verificando PC/SC...");
        readerDetailItem.setEnabled(false);
        popup.add(readerDetailItem);

        popup.addSeparator();

        // 2. Open Diagnostics Panel
        MenuItem diagItem = new MenuItem("Abrir Panel de Diagnóstico");
        diagItem.addActionListener(e -> openDiagnostics());
        popup.add(diagItem);

        // 3. Local Test Verification
        MenuItem testVerifyItem = new MenuItem("Probar Verificación PIN");
        testVerifyItem.addActionListener(e -> runTestVerificationAsync());
        popup.add(testVerifyItem);

        // 4. Development Sandbox Controls (Strictly visible only when ENVIRONMENT=development)
        if (config.isDevelopment()) {
            popup.addSeparator();
            toggleSandboxItem = new MenuItem("Conmutar a Modo Sandbox");
            toggleSandboxItem.addActionListener(e -> toggleSandbox());
            popup.add(toggleSandboxItem);

            simulateCardToggleItem = new MenuItem("Simular Retiro de DNIe (Kill-Switch)");
            simulateCardToggleItem.addActionListener(e -> toggleSimulatedCardPresence());
            popup.add(simulateCardToggleItem);
        }

        popup.addSeparator();

        // 5. Restart WebSocket Server
        MenuItem restartItem = new MenuItem("Reiniciar Conexión WebSocket");
        restartItem.addActionListener(e -> {
            if (restartServerAction != null) {
                new Thread(restartServerAction, "killagent-ws-restart").start();
            }
        });
        popup.add(restartItem);

        // 6. Clean Exit
        MenuItem exitItem = new MenuItem("Salir");
        exitItem.addActionListener(e -> {
            if (exitAction != null) {
                new Thread(exitAction, "killagent-exit").start();
            } else {
                System.exit(0);
            }
        });
        popup.add(exitItem);

        return popup;
    }

    public void openDiagnostics() {
        SwingUtilities.invokeLater(() -> {
            if (diagnosticsDialog == null) {
                diagnosticsDialog = new DiagnosticsDialog(
                        null,
                        config,
                        readerManager,
                        pkcs11Bridge,
                        mockHardwareService,
                        cryptoService,
                        activeConnectionsSupplier,
                        this::runTestVerificationAsync
                );
            }
            diagnosticsDialog.refreshDiagnostics();
            diagnosticsDialog.setVisible(true);
            diagnosticsDialog.toFront();
        });
    }

    private void runTestVerificationAsync() {
        Thread worker = new Thread(() -> {
            HardwareStatus status = readerManager.getStatus();
            if (!status.cardPresent()) {
                SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(
                        null,
                        "No hay ningún DNIe insertado en el lector.\nInserte su tarjeta inteligente para ejecutar la prueba.",
                        "DNIe No Detectado",
                        JOptionPane.WARNING_MESSAGE
                ));
                return;
            }

            setBusyState(true);
            try {
                PinPromptProvider.PinPromptResult prompt = pinPromptProvider.requestPin(
                        "Verificación Local de Diagnóstico",
                        "Verificación local de salud del chip DNIe y validación de PIN."
                );

                if (!prompt.isConfirmed()) {
                    return;
                }

                AuthChallengeResult result = cryptoService.signAuthChallenge(prompt.pin(), TEST_CHALLENGE_NONCE);
                updateStatusDisplay();

                SwingUtilities.invokeLater(() -> {
                    if (diagnosticsDialog != null && diagnosticsDialog.isVisible()) {
                        diagnosticsDialog.refreshDiagnostics();
                    }
                    JOptionPane.showMessageDialog(
                            null,
                            "¡Verificación criptográfica RSA-2048 exitosa!\n\n"
                                    + "Titular: " + result.metadata().getOrDefault("fullName", "N/A") + "\n"
                                    + "DNI: *****" + maskDni(result.metadata().get("dni")) + "\n"
                                    + "Serie Cert.: " + result.metadata().getOrDefault("certificateSerialNumber", "N/A") + "\n"
                                    + "Vigente hasta: " + result.metadata().getOrDefault("validTo", "N/A"),
                            "Diagnóstico de Verificación Exitoso",
                            JOptionPane.INFORMATION_MESSAGE
                    );
                });
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(
                        null,
                        "Fallo en la verificación criptográfica:\n" + ex.getMessage(),
                        "Error Criptográfico",
                        JOptionPane.ERROR_MESSAGE
                ));
            } finally {
                setBusyState(false);
                updateStatusDisplay();
            }
        }, "killagent-test-verify-worker");
        worker.setDaemon(true);
        worker.start();
    }

    private void toggleSandbox() {
        boolean nextState = !readerManager.isMockActive();
        readerManager.setMockMode(nextState);
        updateStatusDisplay();
    }

    private void toggleSimulatedCardPresence() {
        if (!readerManager.isMockActive()) {
            return;
        }
        if (readerManager.getStatus().cardPresent()) {
            readerManager.simulateMockCardRemoval();
        } else {
            readerManager.simulateMockCardInsertion();
        }
        updateStatusDisplay();
    }

    public void setBusyState(boolean busy) {
        this.busySigning = busy;
        updateStatusDisplay();
    }

    public void updateStatusDisplay() {
        Runnable uiUpdate = () -> {
            HardwareStatus status = readerManager.getStatus();
            TrayIconFactory.TrayState visualState = busySigning
                    ? TrayIconFactory.TrayState.BUSY_SIGNING
                    : determineCurrentState();

            if (trayIcon != null) {
                trayIcon.setImage(AssetManager.getTrayIcon(visualState));
                trayIcon.setToolTip("KILLAgent — " + visualState.getDescription());
            }

            String activeDni = readerManager.getActiveCardholderDni();
            String maskedDniSuffix = (activeDni != null && !activeDni.isBlank())
                    ? " | DNI: *****" + maskDni(activeDni)
                    : "";

            String header;
            if (busySigning) {
                header = "● Operación criptográfica en curso..." + maskedDniSuffix;
            } else if (status.isMock()) {
                header = (status.cardPresent() ? "● Sandbox Activo (DNIe Virtual)" : "○ Sandbox (Sin tarjeta)") + maskedDniSuffix;
            } else if (!status.readerPresent()) {
                header = "○ Sin lector de tarjetas conectado";
            } else if (!status.cardPresent()) {
                header = "◐ Lector listo — Inserte su DNIe";
            } else {
                header = "● DNIe Activo (" + status.cardType() + ")" + maskedDniSuffix;
            }

            if (statusHeaderItem != null) {
                statusHeaderItem.setLabel(header);
            }
            if (readerDetailItem != null) {
                String readerLabel = status.readerPresent() && status.readerName() != null
                        ? "Lector: " + truncate(status.readerName(), 38)
                        : "Lector: No detectado";
                readerDetailItem.setLabel(readerLabel);
            }
            if (toggleSandboxItem != null) {
                toggleSandboxItem.setLabel(status.isMock()
                        ? "Desactivar Modo Sandbox (Usar Lector Físico)"
                        : "Conmutar a Modo Sandbox");
            }
            if (simulateCardToggleItem != null) {
                simulateCardToggleItem.setEnabled(status.isMock());
                simulateCardToggleItem.setLabel(status.cardPresent()
                        ? "Simular Retiro de DNIe (Kill-Switch)"
                        : "Simular Inserción de DNIe");
            }
            if (diagnosticsDialog != null && diagnosticsDialog.isVisible()) {
                diagnosticsDialog.refreshDiagnostics();
            }
        };

        if (SwingUtilities.isEventDispatchThread()) {
            uiUpdate.run();
        } else {
            SwingUtilities.invokeLater(uiUpdate);
        }
    }

    private TrayIconFactory.TrayState determineCurrentState() {
        HardwareStatus status = readerManager.getStatus();
        if (status.isMock()) {
            return status.cardPresent()
                    ? TrayIconFactory.TrayState.MOCK_SANDBOX
                    : TrayIconFactory.TrayState.NO_CARD;
        }
        if (!status.readerPresent()) {
            return TrayIconFactory.TrayState.NO_READER;
        }
        if (!status.cardPresent()) {
            return TrayIconFactory.TrayState.NO_CARD;
        }
        return TrayIconFactory.TrayState.CARD_READY;
    }

    private static String maskDni(String dni) {
        if (dni == null || dni.length() < 3) return "***";
        return dni.substring(dni.length() - 3);
    }

    private static String truncate(String text, int maxLen) {
        if (text == null || text.length() <= maxLen) return text;
        return text.substring(0, maxLen - 3) + "...";
    }

    @Override
    public void onCardInserted(String readerName, CardType cardType) {
        cryptoService.resetEstimatedPinAttempts();
        updateStatusDisplay();
        if (config.showBalloonNotifications() && trayIcon != null) {
            SwingUtilities.invokeLater(() -> trayIcon.displayMessage(
                    "DNIe Detectado",
                    "Tarjeta inteligente reconocida en " + readerName + ". Lista para operar.",
                    TrayIcon.MessageType.INFO
            ));
        }
    }

    @Override
    public void onCardRemoved(String readerName) {
        pinPromptProvider.abortActivePromptForCardRemoval();
        pkcs11Bridge.cleanup();
        updateStatusDisplay();
        if (config.showBalloonNotifications() && trayIcon != null) {
            SwingUtilities.invokeLater(() -> trayIcon.displayMessage(
                    "DNIe Retirado — Kill-Switch Activo",
                    "Sesión criptográfica local y web invalidada inmediatamente.",
                    TrayIcon.MessageType.WARNING
            ));
        }
    }

    @Override
    public void onReaderStatusChanged(boolean readerPresent, String readerName) {
        updateStatusDisplay();
        if (config.showBalloonNotifications() && trayIcon != null) {
            SwingUtilities.invokeLater(() -> {
                if (trayIcon == null) {
                    return;
                }
                if (readerPresent) {
                    String displayReader = (readerName != null && !readerName.isBlank())
                            ? readerName
                            : "Dispositivo PC/SC";
                    trayIcon.displayMessage(
                            "Lector Conectado",
                            "Lector Conectado: " + displayReader,
                            TrayIcon.MessageType.INFO
                    );
                } else {
                    trayIcon.displayMessage(
                            "Lector Desconectado",
                            "Lector de tarjetas desconectado",
                            TrayIcon.MessageType.WARNING
                    );
                }
            });
        }
    }
}
