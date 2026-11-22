package pe.ong.chasca.killagent.ui;

import com.formdev.flatlaf.FlatClientProperties;
import pe.ong.chasca.killagent.config.AgentConfig;
import pe.ong.chasca.killagent.crypto.CryptoService;
import pe.ong.chasca.killagent.hardware.CardReaderManager;
import pe.ong.chasca.killagent.hardware.HardwareStatus;
import pe.ong.chasca.killagent.hardware.mock.MockHardwareService;
import pe.ong.chasca.killagent.hardware.pkcs11.Pkcs11Bridge;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.function.IntSupplier;

/**
 * Interactive Diagnostics & Hardware Health Dashboard for KILLAgent.
 * Displays PC/SC terminals, ATR, PKCS#11 driver resolution, certificate details,
 * active WebSocket sessions, and Sandbox Kill-Switch testing controls (in development).
 */
public class DiagnosticsDialog extends JDialog {

    private final AgentConfig config;
    private final CardReaderManager readerManager;
    private final Pkcs11Bridge pkcs11Bridge;
    private final MockHardwareService mockHardwareService;
    private final CryptoService cryptoService;
    private final IntSupplier activeConnectionsSupplier;
    private final Runnable testSignatureTrigger;

    private final JTextArea infoArea;
    private JButton simulateInsertBtn;
    private JButton simulateRemoveBtn;
    private JButton resetPinBtn;

    public DiagnosticsDialog(
            Frame parent,
            AgentConfig config,
            CardReaderManager readerManager,
            Pkcs11Bridge pkcs11Bridge,
            MockHardwareService mockHardwareService,
            CryptoService cryptoService,
            IntSupplier activeConnectionsSupplier,
            Runnable testSignatureTrigger
    ) {
        super(parent, "KILLAgent — Panel de Diagnóstico Zero Trust", false);
        this.config = config;
        this.readerManager = readerManager;
        this.pkcs11Bridge = pkcs11Bridge;
        this.mockHardwareService = mockHardwareService;
        this.cryptoService = cryptoService;
        this.activeConnectionsSupplier = activeConnectionsSupplier != null ? activeConnectionsSupplier : () -> 0;
        this.testSignatureTrigger = testSignatureTrigger;

        setSize(640, 540);
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
        JLabel subtitle = new JLabel("Ancla Criptográfica Local Ch'asca — Aislamiento Loopback 127.0.0.1");
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

        // 3. Bottom Controls (Sandbox Controls in Dev + Standard Actions)
        JPanel bottomContainer = new JPanel(new BorderLayout(8, 8));
        bottomContainer.setOpaque(false);

        if (config.isDevelopment()) {
            JPanel sandboxToolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
            sandboxToolbar.setBorder(BorderFactory.createTitledBorder("Simulador de Eventos Hardware (Sandbox / Dev)"));

            simulateInsertBtn = new JButton("Insertar DNIe Virtual");
            simulateInsertBtn.putClientProperty(FlatClientProperties.STYLE, "arc: 8");
            simulateInsertBtn.addActionListener(e -> {
                readerManager.simulateMockCardInsertion();
                refreshDiagnostics();
            });

            simulateRemoveBtn = new JButton("Retirar DNIe (Kill-Switch)");
            simulateRemoveBtn.setForeground(new Color(247, 37, 133));
            simulateRemoveBtn.putClientProperty(FlatClientProperties.STYLE, "arc: 8");
            simulateRemoveBtn.addActionListener(e -> {
                readerManager.simulateMockCardRemoval();
                refreshDiagnostics();
            });

            resetPinBtn = new JButton("Resetear PIN (3 intentos)");
            resetPinBtn.putClientProperty(FlatClientProperties.STYLE, "arc: 8");
            resetPinBtn.addActionListener(e -> {
                if (mockHardwareService != null) {
                    mockHardwareService.resetPinAttempts();
                }
                cryptoService.resetEstimatedPinAttempts();
                refreshDiagnostics();
            });

            sandboxToolbar.add(simulateInsertBtn);
            sandboxToolbar.add(simulateRemoveBtn);
            sandboxToolbar.add(resetPinBtn);
            bottomContainer.add(sandboxToolbar, BorderLayout.NORTH);
        }

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        if (testSignatureTrigger != null) {
            JButton testVerifyBtn = new JButton("Probar Verificación PIN");
            testVerifyBtn.setFont(new Font("Segoe UI", Font.BOLD, 12));
            testVerifyBtn.setBackground(new Color(114, 9, 183));
            testVerifyBtn.setForeground(Color.WHITE);
            testVerifyBtn.putClientProperty(FlatClientProperties.STYLE, "arc: 8");
            testVerifyBtn.addActionListener(e -> testSignatureTrigger.run());
            actions.add(testVerifyBtn);
        }

        JButton refreshBtn = new JButton("Actualizar");
        refreshBtn.putClientProperty(FlatClientProperties.STYLE, "arc: 8");
        refreshBtn.addActionListener(e -> refreshDiagnostics());

        JButton closeBtn = new JButton("Cerrar");
        closeBtn.putClientProperty(FlatClientProperties.STYLE, "arc: 8");
        closeBtn.addActionListener(e -> setVisible(false));

        actions.add(refreshBtn);
        actions.add(closeBtn);
        bottomContainer.add(actions, BorderLayout.SOUTH);

        content.add(bottomContainer, BorderLayout.SOUTH);
        setContentPane(content);

        refreshDiagnostics();
    }

    public void refreshDiagnostics() {
        HardwareStatus status = readerManager.getStatus();
        boolean isMock = status.isMock();

        if (simulateInsertBtn != null) {
            simulateInsertBtn.setEnabled(isMock && !status.cardPresent());
            simulateRemoveBtn.setEnabled(isMock && status.cardPresent());
            resetPinBtn.setEnabled(isMock);
        }

        String scheme = config.secureWss() ? "wss" : "ws";
        StringBuilder sb = new StringBuilder();

        sb.append("┌── ESTADO DEL DAEMON KILLAGENT ────────────────────────────────────┐\n");
        sb.append("  Perfil de Entorno:     ").append(config.environment().toUpperCase()).append("\n");
        sb.append("  Endpoint Loopback:     ").append(scheme).append("://").append(config.host()).append(":").append(config.port()).append("\n");
        sb.append("  Transporte TLS (WSS):  ").append(config.secureWss() ? "HABILITADO (TLS 1.3/1.2)" : "DESHABILITADO (WS Local)").append("\n");
        sb.append("  Clientes WS Activos:   ").append(activeConnectionsSupplier.getAsInt()).append(" sesión(es)\n");
        sb.append("  Modo firma Digest:     ").append(config.documentDigestSignMode()).append("\n");
        sb.append("  Modo Mock / Sandbox:   ").append(isMock ? "ACTIVO (Emulación Bouncy Castle)" : "INACTIVO (Hardware Físico)").append("\n\n");

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

        if (isMock && mockHardwareService != null) {
            sb.append("┌── CERTIFICADOS SINTÉTICOS SANDBOX (RENIEC PKI) ───────────────────┐\n");
            sb.append("  Intentos PIN Restantes: ").append(mockHardwareService.getRemainingAttempts()).append(" / 3 (Nota: PIN '000000' simula fallo)\n");
            appendCertSummary(sb, "Cert. Autenticación", mockHardwareService.getAuthCertificate());
            appendCertSummary(sb, "Cert. Firma PAdES  ", mockHardwareService.getSignCertificate());
            sb.append("\n");
        }

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

    private void appendCertSummary(StringBuilder sb, String label, X509Certificate cert) {
        if (cert == null) return;
        Map<String, String> meta = CryptoService.extractCertificateMetadata(cert);
        sb.append("  • ").append(label).append(": ")
          .append(CryptoService.formatCanonicalReniecDn(cert))
          .append("\n    Serial=").append(meta.get("certificateSerialNumber"))
          .append(" | Vigente hasta=").append(meta.get("validTo")).append("\n");
    }

    private static String maskLast3(String dni) {
        if (dni == null || dni.length() < 3) return "***";
        return dni.substring(dni.length() - 3);
    }
}
