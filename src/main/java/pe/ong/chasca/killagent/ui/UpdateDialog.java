package pe.ong.chasca.killagent.ui;

import com.formdev.flatlaf.FlatClientProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pe.ong.chasca.killagent.config.AgentConfig;
import pe.ong.chasca.killagent.config.AgentVersion;
import pe.ong.chasca.killagent.update.UpdateInstaller;
import pe.ong.chasca.killagent.update.UpdateManifest;
import pe.ong.chasca.killagent.update.UpdateService;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.net.URI;
import java.nio.file.Path;
import java.util.function.BooleanSupplier;

/**
 * Interactive software update dialog allowing users to inspect release notes,
 * verify cryptographic trust (HTTPS + SHA-256 + optional Ed25519), download packages
 * with live progress, and trigger safe unattended upgrades.
 */
public class UpdateDialog extends JDialog {

    private static final Logger logger = LoggerFactory.getLogger(UpdateDialog.class);

    private final AgentConfig config;
    private final UpdateService updateService;
    private final BooleanSupplier isHardwareBusySupplier;
    private final Runnable shutdownCallback;

    private final JLabel statusTitleLabel;
    private final JLabel securityBadgeLabel;
    private final JTextArea notesArea;
    private final JProgressBar progressBar;
    private final JLabel progressLabel;
    private final JButton checkBtn;
    private final JButton installBtn;
    private final JButton releasePageBtn;

    private volatile UpdateService.UpdateCheckResult currentResult;
    private volatile boolean operationRunning = false;

    public UpdateDialog(
            Frame parent,
            AgentConfig config,
            UpdateService updateService,
            UpdateService.UpdateCheckResult initialResult,
            BooleanSupplier isHardwareBusySupplier,
            Runnable shutdownCallback
    ) {
        super(parent, "KILLAgent — Centro de Actualizaciones", false);
        this.config = config;
        this.updateService = updateService;
        this.isHardwareBusySupplier = isHardwareBusySupplier != null ? isHardwareBusySupplier : () -> false;
        this.shutdownCallback = shutdownCallback;

        setSize(580, 470);
        setMinimumSize(new Dimension(520, 420));
        setLocationRelativeTo(parent);
        setIconImage(AssetManager.getAppIcon());

        JPanel content = new JPanel(new BorderLayout(12, 12));
        content.setBorder(new EmptyBorder(18, 20, 18, 20));

        // 1. Header with Brand Shield + CH'ASKA Logo
        JPanel headerPanel = new JPanel(new BorderLayout(12, 0));
        headerPanel.setOpaque(false);
        ImageIcon shield = AssetManager.getShieldBadge(38);
        if (shield != null) {
            headerPanel.add(new JLabel(shield), BorderLayout.WEST);
        }

        JPanel titleBox = new JPanel();
        titleBox.setOpaque(false);
        titleBox.setLayout(new BoxLayout(titleBox, BoxLayout.Y_AXIS));
        JLabel title = new JLabel("Actualización Segura de KILLAgent");
        title.setFont(new Font("Segoe UI", Font.BOLD, 16));
        title.setForeground(new Color(0, 245, 212));
        JLabel subtitle = new JLabel(
                "Versión instalada: v" + AgentVersion.getVersion()
                        + "  |  Canal: " + config.updateChannel().toUpperCase()
        );
        subtitle.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        titleBox.add(title);
        titleBox.add(subtitle);
        headerPanel.add(titleBox, BorderLayout.CENTER);

        ImageIcon logo = AssetManager.getBrandLogo();
        if (logo != null) {
            headerPanel.add(new JLabel(logo), BorderLayout.EAST);
        }
        content.add(headerPanel, BorderLayout.NORTH);

        // 2. Center Status + Notes
        JPanel centerPanel = new JPanel(new BorderLayout(8, 8));
        centerPanel.setOpaque(false);

        JPanel summaryBox = new JPanel(new BorderLayout(6, 4));
        summaryBox.setBorder(new EmptyBorder(10, 12, 10, 12));
        summaryBox.putClientProperty(FlatClientProperties.STYLE, "arc: 10; background: darken($Panel.background, 3%)");

        statusTitleLabel = new JLabel("Listo para comprobar actualizaciones");
        statusTitleLabel.setFont(new Font("Segoe UI", Font.BOLD, 13));
        securityBadgeLabel = new JLabel("Política: HTTPS + SHA-256");
        securityBadgeLabel.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        securityBadgeLabel.setForeground(new Color(140, 160, 180));

        summaryBox.add(statusTitleLabel, BorderLayout.NORTH);
        summaryBox.add(securityBadgeLabel, BorderLayout.SOUTH);
        centerPanel.add(summaryBox, BorderLayout.NORTH);

        notesArea = new JTextArea();
        notesArea.setEditable(false);
        notesArea.setLineWrap(true);
        notesArea.setWrapStyleWord(true);
        notesArea.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        notesArea.setMargin(new Insets(10, 12, 10, 12));
        JScrollPane notesScroll = new JScrollPane(notesArea);
        notesScroll.putClientProperty(FlatClientProperties.STYLE, "arc: 10");
        centerPanel.add(notesScroll, BorderLayout.CENTER);

        JPanel progressBox = new JPanel(new BorderLayout(6, 4));
        progressBox.setOpaque(false);
        progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(true);
        progressBar.setVisible(false);
        progressLabel = new JLabel(" ");
        progressLabel.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        progressBox.add(progressLabel, BorderLayout.NORTH);
        progressBox.add(progressBar, BorderLayout.CENTER);
        centerPanel.add(progressBox, BorderLayout.SOUTH);

        content.add(centerPanel, BorderLayout.CENTER);

        // 3. Bottom Action Buttons
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));

        releasePageBtn = new JButton("Ver Notas");
        releasePageBtn.putClientProperty(FlatClientProperties.STYLE, "arc: 8");
        releasePageBtn.setVisible(false);
        releasePageBtn.addActionListener(e -> openReleaseNotesUrl());

        checkBtn = new JButton("Comprobar Ahora");
        checkBtn.putClientProperty(FlatClientProperties.STYLE, "arc: 8");
        checkBtn.addActionListener(e -> runCheckAsync());

        installBtn = new JButton("Descargar e Instalar");
        installBtn.setFont(new Font("Segoe UI", Font.BOLD, 12));
        installBtn.setBackground(new Color(114, 9, 183));
        installBtn.setForeground(Color.WHITE);
        installBtn.putClientProperty(FlatClientProperties.STYLE, "arc: 8");
        installBtn.setEnabled(false);
        installBtn.addActionListener(e -> runDownloadAndInstallAsync());

        JButton closeBtn = new JButton("Cerrar");
        closeBtn.putClientProperty(FlatClientProperties.STYLE, "arc: 8");
        closeBtn.addActionListener(e -> setVisible(false));

        actions.add(releasePageBtn);
        actions.add(checkBtn);
        actions.add(installBtn);
        actions.add(closeBtn);
        content.add(actions, BorderLayout.SOUTH);

        setContentPane(content);
        applyResult(initialResult);
    }

    public void applyResult(UpdateService.UpdateCheckResult result) {
        this.currentResult = result;
        if (result == null) {
            statusTitleLabel.setText("Pulsa 'Comprobar Ahora' para consultar la última versión publicada.");
            statusTitleLabel.setForeground(UIManager.getColor("Label.foreground"));
            securityBadgeLabel.setText("Origen configurado: " + config.updateManifestUrl());
            notesArea.setText("Canal activo: " + config.updateChannel()
                    + "\nVerificación de firma Ed25519: "
                    + (!config.updateSigningPublicKey().isBlank() ? "Clave pública fijada" : "No fijada (HTTPS + SHA-256)"));
            installBtn.setEnabled(false);
            releasePageBtn.setVisible(false);
            return;
        }

        switch (result.status()) {
            case UPDATE_AVAILABLE -> {
                String mandatoryTag = result.mandatory() ? " [OBLIGATORIA]" : "";
                statusTitleLabel.setText("Nueva versión disponible: v" + result.availableVersion() + mandatoryTag);
                statusTitleLabel.setForeground(result.mandatory() ? new Color(247, 37, 133) : new Color(0, 245, 212));

                UpdateManifest manifest = result.manifest();
                UpdateManifest.ArtifactInfo artifact = manifest != null && result.selectedArtifactKey() != null
                        ? manifest.artifacts().get(result.selectedArtifactKey())
                        : null;

                String trustMode = result.signatureVerified()
                        ? "Verificado con firma Ed25519 + SHA-256"
                        : "Transporte HTTPS + verificación SHA-256";
                String sizeText = (artifact != null && artifact.sizeBytes() > 0)
                        ? String.format(" | Paquete: %s (%.1f MB)", artifact.fileName(), artifact.sizeBytes() / (1024.0 * 1024.0))
                        : "";
                securityBadgeLabel.setText(trustMode + sizeText);

                String notes = (manifest != null && manifest.releaseNotes() != null && !manifest.releaseNotes().isBlank())
                        ? manifest.releaseNotes()
                        : "Actualización de mantenimiento y mejoras de seguridad para KILLAgent.";
                notesArea.setText(notes);
                notesArea.setCaretPosition(0);

                installBtn.setEnabled(!operationRunning);
                boolean hasUrl = manifest != null && manifest.releaseNotesUrl() != null && !manifest.releaseNotesUrl().isBlank();
                releasePageBtn.setVisible(hasUrl);
            }
            case UP_TO_DATE -> {
                statusTitleLabel.setText("KILLAgent está actualizado (v" + result.currentVersion() + ")");
                statusTitleLabel.setForeground(new Color(6, 214, 160));
                String trust = result.signatureVerified() ? "Manifiesto verificado con Ed25519" : "Verificación HTTPS completada";
                securityBadgeLabel.setText(trust + " | Origen: " + config.updateManifestUrl());
                notesArea.setText(result.message());
                installBtn.setEnabled(false);
                releasePageBtn.setVisible(false);
            }
            case DISABLED -> {
                statusTitleLabel.setText("Actualizaciones automáticas deshabilitadas");
                statusTitleLabel.setForeground(new Color(245, 158, 11));
                securityBadgeLabel.setText("Habilite UPDATE_ENABLED=true en .env para recibir actualizaciones.");
                notesArea.setText(result.message());
                installBtn.setEnabled(false);
                releasePageBtn.setVisible(false);
            }
            case ERROR -> {
                statusTitleLabel.setText("No se pudo comprobar actualizaciones");
                statusTitleLabel.setForeground(new Color(247, 37, 133));
                securityBadgeLabel.setText("Origen: " + config.updateManifestUrl());
                notesArea.setText(result.message());
                installBtn.setEnabled(false);
                releasePageBtn.setVisible(false);
            }
        }
    }

    public void runCheckAsync() {
        if (operationRunning) {
            return;
        }
        operationRunning = true;
        checkBtn.setEnabled(false);
        installBtn.setEnabled(false);
        progressBar.setVisible(true);
        progressBar.setIndeterminate(true);
        progressBar.setString("Consultando manifiesto...");
        progressLabel.setText("Conectando con servidor seguro...");

        Thread worker = new Thread(() -> {
            UpdateService.UpdateCheckResult res = updateService.checkForUpdates();
            SwingUtilities.invokeLater(() -> {
                operationRunning = false;
                checkBtn.setEnabled(true);
                progressBar.setIndeterminate(false);
                progressBar.setVisible(false);
                progressLabel.setText(" ");
                applyResult(res);
            });
        }, "killagent-update-check-ui");
        worker.setDaemon(true);
        worker.start();
    }

    private void runDownloadAndInstallAsync() {
        UpdateService.UpdateCheckResult snapshot = currentResult;
        if (operationRunning || snapshot == null || !snapshot.isUpdateAvailable()) {
            return;
        }
        if (isHardwareBusySupplier.getAsBoolean()) {
            JOptionPane.showMessageDialog(
                    this,
                    "Hay una operación de firma o validación PIN en curso.\nComplete o cancele la operación actual antes de instalar la actualización.",
                    "Operación Criptográfica Activa",
                    JOptionPane.WARNING_MESSAGE
            );
            return;
        }

        operationRunning = true;
        checkBtn.setEnabled(false);
        installBtn.setEnabled(false);
        progressBar.setVisible(true);
        progressBar.setIndeterminate(false);
        progressBar.setValue(0);
        progressBar.setString("0%");
        progressLabel.setText("Descargando paquete verificado...");

        Thread worker = new Thread(() -> {
            try {
                Path downloaded = updateService.downloadAndVerifyArtifact(
                        snapshot.manifest(),
                        snapshot.selectedArtifactKey(),
                        (read, total) -> SwingUtilities.invokeLater(() -> {
                            if (total > 0) {
                                int pct = (int) Math.min(100L, (read * 100L) / total);
                                progressBar.setIndeterminate(false);
                                progressBar.setValue(pct);
                                progressBar.setString(pct + "%");
                                progressLabel.setText(String.format(
                                        "Descargando: %.1f MB / %.1f MB",
                                        read / (1024.0 * 1024.0),
                                        total / (1024.0 * 1024.0)
                                ));
                            } else {
                                progressBar.setIndeterminate(true);
                                progressBar.setString("Descargando...");
                            }
                        })
                );

                SwingUtilities.invokeLater(() -> {
                    progressBar.setIndeterminate(false);
                    progressBar.setValue(100);
                    progressBar.setString("SHA-256 Verificado");
                    progressLabel.setText("Paquete validado criptográficamente: " + downloaded.getFileName());

                    int choice = JOptionPane.showConfirmDialog(
                            this,
                            "Paquete descargado y verificado correctamente (SHA-256 válido):\n"
                                    + downloaded.getFileName() + "\n\n"
                                    + "¿Desea cerrar KILLAgent temporalmente para aplicar la actualización v"
                                    + snapshot.availableVersion() + " ahora?",
                            "Confirmar Instalación de Actualización",
                            JOptionPane.YES_NO_OPTION,
                            JOptionPane.QUESTION_MESSAGE
                    );

                    operationRunning = false;
                    checkBtn.setEnabled(true);
                    installBtn.setEnabled(true);

                    if (choice == JOptionPane.YES_OPTION) {
                        try {
                            boolean automated = UpdateInstaller.applyVerifiedUpdate(
                                    downloaded,
                                    snapshot.availableVersion(),
                                    shutdownCallback
                            );
                            if (!automated) {
                                JOptionPane.showMessageDialog(
                                        this,
                                        "Se abrió la carpeta con la actualización verificada en:\n" + downloaded.toAbsolutePath()
                                                + "\n\nEjecute el instalador manualmente para completar la actualización.",
                                        "Actualización Lista",
                                        JOptionPane.INFORMATION_MESSAGE
                                );
                            }
                        } catch (Exception applyEx) {
                            logger.error("Failed to launch updater script: {}", applyEx.getMessage(), applyEx);
                            JOptionPane.showMessageDialog(
                                    this,
                                    "Error al iniciar el instalador:\n" + applyEx.getMessage(),
                                    "Error de Instalación",
                                    JOptionPane.ERROR_MESSAGE
                            );
                        }
                    }
                });
            } catch (Exception ex) {
                logger.warn("Update download/verification failed: {}", ex.getMessage());
                SwingUtilities.invokeLater(() -> {
                    operationRunning = false;
                    checkBtn.setEnabled(true);
                    installBtn.setEnabled(true);
                    progressBar.setVisible(false);
                    progressLabel.setText(" ");
                    JOptionPane.showMessageDialog(
                            this,
                            "No se pudo completar la descarga o verificación:\n" + ex.getMessage(),
                            "Error de Actualización",
                            JOptionPane.ERROR_MESSAGE
                    );
                });
            }
        }, "killagent-update-download");
        worker.setDaemon(true);
        worker.start();
    }

    private void openReleaseNotesUrl() {
        UpdateService.UpdateCheckResult snapshot = currentResult;
        if (snapshot == null || snapshot.manifest() == null || snapshot.manifest().releaseNotesUrl() == null) {
            return;
        }
        try {
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                Desktop.getDesktop().browse(URI.create(snapshot.manifest().releaseNotesUrl()));
            }
        } catch (Exception e) {
            logger.debug("Could not open release notes URL: {}", e.getMessage());
        }
    }
}
