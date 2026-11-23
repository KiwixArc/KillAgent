package pe.ong.chasca.killagent.ui;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pe.ong.chasca.killagent.config.AgentConfig;
import pe.ong.chasca.killagent.config.AgentVersion;
import pe.ong.chasca.killagent.crypto.CryptoService;
import pe.ong.chasca.killagent.hardware.CardReaderManager;
import pe.ong.chasca.killagent.hardware.CardType;
import pe.ong.chasca.killagent.hardware.HardwareListener;
import pe.ong.chasca.killagent.hardware.HardwareStatus;
import pe.ong.chasca.killagent.hardware.pkcs11.Pkcs11Bridge;
import pe.ong.chasca.killagent.system.WindowsStartupManager;
import pe.ong.chasca.killagent.update.UpdateService;

import javax.swing.*;
import java.awt.*;
import java.util.function.BooleanSupplier;
import java.util.function.IntSupplier;

/**
 * Manages Windows 11 Taskbar System Tray presence, dynamic SVG state icon rendering,
 * masked cardholder identity status pill, auto-start toggle, update notifications,
 * and contextual operational actions.
 */
public class SystemTrayManager implements HardwareListener {

    private static final Logger logger = LoggerFactory.getLogger(SystemTrayManager.class);

    private final AgentConfig config;
    private final CardReaderManager readerManager;
    private final Pkcs11Bridge pkcs11Bridge;
    private final CryptoService cryptoService;
    private final PinPromptProvider pinPromptProvider;
    private final UpdateService updateService;
    private final Runnable restartServerAction;
    private final Runnable exitAction;

    private volatile IntSupplier activeConnectionsSupplier = () -> 0;
    private volatile BooleanSupplier externalBusySupplier = () -> false;
    private volatile boolean busySigning = false;

    private TrayIcon trayIcon;
    private MenuItem statusHeaderItem;
    private MenuItem readerDetailItem;
    private MenuItem updateMenuItem;
    private CheckboxMenuItem autoStartItem;
    private DiagnosticsDialog diagnosticsDialog;
    private UpdateDialog updateDialog;
    private volatile UpdateService.UpdateCheckResult latestUpdateResult;

    public SystemTrayManager(
            AgentConfig config,
            CardReaderManager readerManager,
            Pkcs11Bridge pkcs11Bridge,
            CryptoService cryptoService,
            PinPromptProvider pinPromptProvider,
            UpdateService updateService,
            Runnable restartServerAction,
            Runnable exitAction
    ) {
        this.config = config;
        this.readerManager = readerManager;
        this.pkcs11Bridge = pkcs11Bridge;
        this.cryptoService = cryptoService;
        this.pinPromptProvider = pinPromptProvider;
        this.updateService = updateService;
        this.restartServerAction = restartServerAction;
        this.exitAction = exitAction;

        readerManager.addListener(this);
    }

    public void setActiveConnectionsSupplier(IntSupplier supplier) {
        if (supplier != null) {
            this.activeConnectionsSupplier = supplier;
        }
    }

    public void setBusyCheckSupplier(BooleanSupplier supplier) {
        if (supplier != null) {
            this.externalBusySupplier = supplier;
        }
    }

    public boolean isAnyOperationBusy() {
        return busySigning || externalBusySupplier.getAsBoolean();
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
            trayIcon = new TrayIcon(initialImage, "KILLAgent — Ch'aska Zero Trust Anchor", popup);
            trayIcon.setImageAutoSize(true);
            trayIcon.addActionListener(e -> openDiagnostics());

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
        if (updateDialog != null) {
            SwingUtilities.invokeLater(() -> updateDialog.dispose());
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

        MenuItem versionItem = new MenuItem("KILLAgent v" + AgentVersion.getVersion() + " (" + config.updateChannel() + ")");
        versionItem.setEnabled(false);
        popup.add(versionItem);

        popup.addSeparator();

        // 2. Open Diagnostics Panel
        MenuItem diagItem = new MenuItem("Abrir Panel de Diagnóstico");
        diagItem.addActionListener(e -> openDiagnostics());
        popup.add(diagItem);

        // 3. Check Updates
        updateMenuItem = new MenuItem("Buscar Actualizaciones...");
        updateMenuItem.addActionListener(e -> checkUpdatesInteractive());
        popup.add(updateMenuItem);

        // 4. Windows Auto-Start Checkbox
        if (WindowsStartupManager.isSupported()) {
            autoStartItem = new CheckboxMenuItem(
                    "Iniciar automáticamente con Windows",
                    WindowsStartupManager.isAutoStartEnabled()
            );
            autoStartItem.addItemListener(e -> {
                boolean desired = autoStartItem.getState();
                boolean updated = WindowsStartupManager.setAutoStartEnabled(desired);
                if (!updated) {
                    autoStartItem.setState(WindowsStartupManager.isAutoStartEnabled());
                    SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(
                            null,
                            "No se pudo modificar el inicio automático.\nEjecute KILLAgent desde su instalador (.exe / .msi) o JAR compilado.",
                            "Inicio Automático",
                            JOptionPane.WARNING_MESSAGE
                    ));
                }
                if (diagnosticsDialog != null && diagnosticsDialog.isVisible()) {
                    diagnosticsDialog.refreshDiagnostics();
                }
            });
            popup.add(autoStartItem);
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
                        updateService,
                        activeConnectionsSupplier,
                        this::checkUpdatesInteractive
                );
            }
            diagnosticsDialog.refreshDiagnostics();
            diagnosticsDialog.setVisible(true);
            diagnosticsDialog.toFront();
        });
    }

    public void checkUpdatesInteractive() {
        SwingUtilities.invokeLater(() -> {
            openUpdatesDialog(latestUpdateResult);
            if (updateDialog != null) {
                updateDialog.runCheckAsync();
            }
        });
    }

    public void notifyUpdateAvailable(UpdateService.UpdateCheckResult result) {
        if (result == null || !result.isUpdateAvailable()) {
            return;
        }
        this.latestUpdateResult = result;
        SwingUtilities.invokeLater(() -> {
            if (updateMenuItem != null) {
                updateMenuItem.setLabel("★ Actualización Disponible (v" + result.availableVersion() + ")...");
            }
            if (diagnosticsDialog != null && diagnosticsDialog.isVisible()) {
                diagnosticsDialog.refreshDiagnostics();
            }
            if (updateDialog != null && updateDialog.isVisible()) {
                updateDialog.applyResult(result);
            }
            if (config.showBalloonNotifications() && trayIcon != null) {
                String mandatoryPrefix = result.mandatory() ? "[Obligatoria] " : "";
                trayIcon.displayMessage(
                        "Actualización de KILLAgent Disponible",
                        mandatoryPrefix + "Nueva versión v" + result.availableVersion()
                                + " lista. Clic derecho -> Buscar Actualizaciones...",
                        TrayIcon.MessageType.INFO
                );
            }
        });
    }

    private void openUpdatesDialog(UpdateService.UpdateCheckResult result) {
        if (updateDialog == null) {
            updateDialog = new UpdateDialog(
                    null,
                    config,
                    updateService,
                    result,
                    this::isAnyOperationBusy,
                    exitAction
            );
        } else if (result != null) {
            updateDialog.applyResult(result);
        }
        updateDialog.setVisible(true);
        updateDialog.toFront();
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
                trayIcon.setToolTip("KILLAgent v" + AgentVersion.getVersion() + " — " + visualState.getDescription());
            }

            String activeDni = readerManager.getActiveCardholderDni();
            String maskedDniSuffix = (activeDni != null && !activeDni.isBlank())
                    ? " | DNI: *****" + maskDni(activeDni)
                    : "";

            String header;
            if (busySigning) {
                header = "● Operación criptográfica en curso..." + maskedDniSuffix;
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
