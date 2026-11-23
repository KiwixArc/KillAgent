package pe.ong.chasca.killagent.ui;

import com.formdev.flatlaf.FlatClientProperties;
import pe.ong.chasca.killagent.config.AgentConfig;
import pe.ong.chasca.killagent.config.AgentVersion;
import pe.ong.chasca.killagent.config.AppPaths;
import pe.ong.chasca.killagent.hardware.CardReaderManager;
import pe.ong.chasca.killagent.hardware.HardwareStatus;
import pe.ong.chasca.killagent.hardware.pkcs11.Pkcs11Bridge;
import pe.ong.chasca.killagent.system.WindowsStartupManager;
import pe.ong.chasca.killagent.update.UpdateInstaller;
import pe.ong.chasca.killagent.update.UpdateService;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.nio.file.Files;
import java.util.List;
import java.util.function.IntSupplier;

/**
 * Interactive Diagnostics & Hardware Health Dashboard for KILLAgent.
 * Displays PC/SC terminals, ATR, PKCS#11 driver resolution, runtime update status,
 * Windows auto-start state, active WebSocket sessions, and Zero Trust origin rules.
 */
public class DiagnosticsDialog extends JDialog {

    private final AgentConfig config;
    private final CardReaderManager readerManager;
    private final Pkcs11Bridge pkcs11Bridge;
    private final UpdateService updateService;
    private final IntSupplier activeConnectionsSupplier;
    private final Runnable checkUpdatesAction;

    private final JTextArea infoArea;

    public DiagnosticsDialog(
            Frame parent,
            AgentConfig config,
            CardReaderManager readerManager,
            Pkcs11Bridge pkcs11Bridge,
            UpdateService updateService,
            IntSupplier activeConnectionsSupplier,
            Runnable checkUpdatesAction
    ) {
        super(parent, "KILLAgent — Panel de Diagnóstico Zero Trust", false);
        this.config = config;
        this.readerManager = readerManager;
        this.pkcs11Bridge = pkcs11Bridge;
        this.updateService = updateService;
        this.activeConnectionsSupplier = activeConnectionsSupplier != null ? activeConnectionsSupplier : () -> 0;
        this.checkUpdatesAction = checkUpdatesAction;

        setSize(650, 540);
        setMinimumSize(new Dimension(560, 460));
        setLocationRelativeTo(parent);
        setAlwaysOnTop(false);
        setIconImage(AssetManager.getAppIcon());

        JPanel content = new JPanel(new BorderLayout(12, 12));
        content.setBorder(new EmptyBorder(18, 20, 18, 20));

        // 1. Header with Brand Shield + Title
        JPanel headerPanel = new JPanel(new BorderLayout(12, 0));
        headerPanel.setOpaque(false);
        ImageIcon shield = AssetManager.getShieldBadge(38);
        if (shield != null) {
            headerPanel.add(new JLabel(shield), BorderLayout.WEST);
        }

        JPanel titleBox = new JPanel();
        titleBox.setOpaque(false);
        titleBox.setLayout(new BoxLayout(titleBox, BoxLayout.Y_AXIS));
        JLabel title = new JLabel("Diagnóstico de Hardware PC/SC & PKCS#11");
        title.setFont(new Font("Segoe UI", Font.BOLD, 16));
        title.setForeground(new Color(0, 245, 212));
        JLabel subtitle = new JLabel("Ancla Criptográfica Local Ch'aska — Aislamiento Loopback 127.0.0.1");
        subtitle.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        titleBox.add(title);
        titleBox.add(subtitle);
        headerPanel.add(titleBox, BorderLayout.CENTER);

        ImageIcon logo = AssetManager.getBrandLogo();
        if (logo != null) {
            headerPanel.add(new JLabel(logo), BorderLayout.EAST);
        }
        content.add(headerPanel, BorderLayout.NORTH);

        // 2. Center Diagnostic Report View
        infoArea = new JTextArea();
        infoArea.setEditable(false);
        infoArea.setFont(new Font("Consolas", Font.PLAIN, 12));
        infoArea.setMargin(new Insets(12, 14, 12, 14));
        infoArea.putClientProperty(FlatClientProperties.STYLE, "background: darken($Panel.background, 3%)");

        JScrollPane scrollPane = new JScrollPane(infoArea);
        scrollPane.putClientProperty(FlatClientProperties.STYLE, "arc: 10");
        content.add(scrollPane, BorderLayout.CENTER);

        // 3. Bottom Controls
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));

        JButton dataDirBtn = new JButton("Carpeta de Datos");
        dataDirBtn.putClientProperty(FlatClientProperties.STYLE, "arc: 8");
        dataDirBtn.addActionListener(e -> openDataDirectory());
        actions.add(dataDirBtn);

        if (checkUpdatesAction != null) {
            JButton updatesBtn = new JButton("Buscar Actualizaciones");
            updatesBtn.setFont(new Font("Segoe UI", Font.BOLD, 12));
            updatesBtn.setBackground(new Color(114, 9, 183));
            updatesBtn.setForeground(Color.WHITE);
            updatesBtn.putClientProperty(FlatClientProperties.STYLE, "arc: 8");
            updatesBtn.addActionListener(e -> this.checkUpdatesAction.run());
            actions.add(updatesBtn);
        }

        JButton refreshBtn = new JButton("Actualizar");
        refreshBtn.putClientProperty(FlatClientProperties.STYLE, "arc: 8");
        refreshBtn.addActionListener(e -> refreshDiagnostics());

        JButton closeBtn = new JButton("Cerrar");
        closeBtn.putClientProperty(FlatClientProperties.STYLE, "arc: 8");
        closeBtn.addActionListener(e -> setVisible(false));

        actions.add(refreshBtn);
        actions.add(closeBtn);

        content.add(actions, BorderLayout.SOUTH);
        setContentPane(content);

        refreshDiagnostics();
    }

    public void refreshDiagnostics() {
        HardwareStatus status = readerManager.getStatus();
        String scheme = config.secureWss() ? "wss" : "ws";
        StringBuilder sb = new StringBuilder();

        sb.append("┌── ESTADO DEL DAEMON KILLAGENT ────────────────────────────────────┐\n");
        sb.append("  Versión Instalada:     ").append(AgentVersion.getDisplayVersion()).append("\n");
        sb.append("  Modo de Ejecución:     ").append(UpdateInstaller.detectLaunchMode()).append("\n");
        sb.append("  Perfil de Entorno:     ").append(config.environment().toUpperCase()).append("\n");
        sb.append("  Endpoint Loopback:     ").append(scheme).append("://").append(config.host()).append(":").append(config.port()).append("\n");
        sb.append("  Transporte TLS (WSS):  ").append(config.secureWss() ? "HABILITADO (TLS 1.3/1.2)" : "DESHABILITADO (WS Local)").append("\n");
        sb.append("  Clientes WS Activos:   ").append(activeConnectionsSupplier.getAsInt()).append(" sesión(es)\n");
        sb.append("  Modo firma Digest:     ").append(config.documentDigestSignMode()).append("\n");
        sb.append("  Inicio con Windows:    ").append(WindowsStartupManager.isAutoStartEnabled() ? "HABILITADO" : "DESHABILITADO").append("\n\n");

        sb.append("┌── SISTEMA DE ACTUALIZACIONES AUTOMÁTICAS ─────────────────────────┐\n");
        sb.append("  Estado:                ").append(config.updateEnabled() ? "HABILITADO" : "DESHABILITADO").append("\n");
        sb.append("  Canal / Intervalo:     ").append(config.updateChannel()).append(" (cada ").append(config.updateCheckIntervalHours()).append("h)\n");
        sb.append("  Firma Ed25519:         ").append(!config.updateSigningPublicKey().isBlank() ? "ACTIVADA (Clave pública fijada)" : "NO FIJADA (Solo HTTPS + SHA-256)").append("\n");
        sb.append("  Manifiesto Remoto:     ").append(config.updateManifestUrl()).append("\n");
        UpdateService.UpdateCheckResult lastUpdate = updateService != null ? updateService.getLastResult() : null;
        if (lastUpdate != null) {
            sb.append("  Última Comprobación:   ").append(lastUpdate.status()).append(" — ").append(lastUpdate.message()).append("\n");
        } else {
            sb.append("  Última Comprobación:   Pendiente\n");
        }
        sb.append("\n");

        sb.append("┌── SUBSISTEMA SMART CARD (PC/SC WinSCard) ─────────────────────────┐\n");
        sb.append("  Lector Detectado:      ").append(status.readerPresent() ? "SÍ" : "NO").append("\n");
        sb.append("  Modelo del Lector:     ").append(status.readerName() != null ? status.readerName() : "Ninguno").append("\n");
        sb.append("  Tarjeta DNIe Presente: ").append(status.cardPresent() ? "SÍ (Lista)" : "NO").append("\n");
        sb.append("  Clasificación Chip:    ").append(status.cardType()).append("\n");
        String atr = readerManager.getLastDetectedAtrHex();
        sb.append("  ATR (Answer To Reset): ").append(atr != null && !atr.isEmpty() ? atr : "N/A").append("\n");

        String holderDni = readerManager.getActiveCardholderDni();
        String holderName = readerManager.getActiveCardholderName();
        if (holderDni != null && !holderDni.isBlank()) {
            sb.append("  Titular Identificado:  ").append(holderName != null ? holderName : "N/A")
              .append(" (DNI: *****").append(maskLast3(holderDni)).append(")\n");
        }
        sb.append("\n");

        sb.append("┌── DRIVERS PKCS#11 EN ESTACIÓN DE TRABAJO WINDOWS ─────────────────┐\n");
        if (pkcs11Bridge != null) {
            List<String> drivers = pkcs11Bridge.inspectInstalledDrivers();
            for (String line : drivers) {
                sb.append("  ").append(line).append("\n");
            }
        }
        sb.append("\n");

        sb.append("┌── LISTA BLANCA DE ORÍGENES ZERO TRUST (ANTI-CSWSH) ───────────────┐\n");
        for (String origin : config.allowedOrigins()) {
            sb.append("  • ").append(origin).append("\n");
        }

        infoArea.setText(sb.toString());
        infoArea.setCaretPosition(0);
    }

    private void openDataDirectory() {
        try {
            java.nio.file.Path dataDir = AppPaths.baseDataDir();
            Files.createDirectories(dataDir);
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.OPEN)) {
                Desktop.getDesktop().open(dataDir.toFile());
            }
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(
                    this,
                    "No se pudo abrir la carpeta de datos:\n" + AppPaths.baseDataDir(),
                    "Carpeta de Datos",
                    JOptionPane.INFORMATION_MESSAGE
            );
        }
    }

    private static String maskLast3(String dni) {
        if (dni == null || dni.length() < 3) return "***";
        return dni.substring(dni.length() - 3);
    }
}
