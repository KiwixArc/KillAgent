package pe.ong.chasca.killagent.ui;

import com.formdev.flatlaf.FlatClientProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pe.ong.chasca.killagent.hardware.CardReaderManager;
import pe.ong.chasca.killagent.hardware.CardType;
import pe.ong.chasca.killagent.hardware.HardwareListener;
import pe.ong.chasca.killagent.hardware.HardwareStatus;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Login-only Swing modal instructing the user to connect a PC/SC reader and/or insert their DNIe 3.0.
 * Subscribes live to {@link CardReaderManager} events, displays real-time reader status,
 * enforces a bounded countdown using {@link CountdownWheelComponent}, and dismisses automatically
 * on the EDT the moment the card is inserted.
 */
public class WaitForCardDialog extends JDialog {

    private static final Logger logger = LoggerFactory.getLogger(WaitForCardDialog.class);
    public static final int DEFAULT_TIMEOUT_SECONDS = 30;

    private static final String HEADER_TITLE = "Inserte su DNI Electrónico";
    private static final String READER_DISCONNECTED_TEXT = "Lector de tarjetas no detectado — conecte su lectora";
    private static final Color READER_CONNECTED_COLOR = CountdownWheelComponent.NORMAL_COUNTDOWN_COLOR;
    private static final Color READER_DISCONNECTED_COLOR = CountdownWheelComponent.WARNING_COUNTDOWN_COLOR;

    private final CardReaderManager readerManager;
    private final JPanel readerStatusBox;
    private final JLabel readerStatusLabel;
    private final DialogUiSupport.CountdownRow countdownRow;
    private final AtomicBoolean listenerRegistered = new AtomicBoolean(false);

    private boolean settled = false;
    private CardWaitProvider.WaitOutcome outcome = CardWaitProvider.WaitOutcome.USER_CANCELLED;

    private final HardwareListener hardwareListener = new HardwareListener() {
        @Override
        public void onCardInserted(String readerName, CardType cardType) {
            SwingUtilities.invokeLater(() -> {
                updateReaderStatusBanner(true, readerName);
                settleWithOutcome(CardWaitProvider.WaitOutcome.CARD_READY);
            });
        }

        @Override
        public void onCardRemoved(String readerName) {
            SwingUtilities.invokeLater(() -> updateReaderStatusBanner(readerManager.getStatus()));
        }

        @Override
        public void onReaderStatusChanged(boolean readerPresent, String readerName) {
            SwingUtilities.invokeLater(() -> updateReaderStatusBanner(readerPresent, readerName));
        }
    };

    public WaitForCardDialog(
            Frame parent,
            CardReaderManager readerManager,
            String title,
            String operationHtmlDetails
    ) {
        this(parent, readerManager, title, operationHtmlDetails, DEFAULT_TIMEOUT_SECONDS);
    }

    public WaitForCardDialog(
            Frame parent,
            CardReaderManager readerManager,
            String title,
            String operationHtmlDetails,
            int timeoutSeconds
    ) {
        super(
                parent,
                (title != null && !title.isBlank()) ? title.trim() : HEADER_TITLE,
                true
        );
        this.readerManager = Objects.requireNonNull(readerManager, "readerManager must not be null");
        int effectiveTimeout = Math.max(0, timeoutSeconds);

        setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);
        setAlwaysOnTop(true);
        setResizable(false);
        setIconImage(AssetManager.getAppIcon());

        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        mainPanel.setBorder(new EmptyBorder(20, 26, 20, 26));

        // 1. Top Branding Row (Zero Trust Shield Badge + Ch'asca Wordmark)
        JPanel brandPanel = DialogUiSupport.createBrandPanel();
        if (brandPanel != null) {
            mainPanel.add(brandPanel);
            mainPanel.add(Box.createVerticalStrut(10));
        }

        // 2. Main Header
        JLabel headerLabel = new JLabel("<html><div style='text-align: center; width: 290px; color: #00F5D4;'>"
                + DialogUiSupport.escapeHtml(HEADER_TITLE) + "</div></html>");
        headerLabel.setFont(new Font("Segoe UI", Font.BOLD, 15));
        headerLabel.setForeground(READER_CONNECTED_COLOR);
        headerLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        mainPanel.add(headerLabel);

        mainPanel.add(Box.createVerticalStrut(6));

        // 3. Operation Context Details
        String effectiveDetails = (operationHtmlDetails != null && !operationHtmlDetails.isBlank())
                ? operationHtmlDetails
                : DialogUiSupport.escapeHtml((title != null && !title.isBlank()) ? title.trim() : HEADER_TITLE);
        JLabel detailLabel = new JLabel("<html><div style='text-align: center; width: 290px; color: #B8C2CC;'>"
                + effectiveDetails + "</div></html>");
        detailLabel.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        detailLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        mainPanel.add(detailLabel);

        mainPanel.add(Box.createVerticalStrut(16));

        // 4. Live PC/SC Reader Connection Banner
        readerStatusBox = new JPanel(new BorderLayout());
        Dimension statusBoxSize = new Dimension(310, 56);
        readerStatusBox.setPreferredSize(statusBoxSize);
        readerStatusBox.setMinimumSize(statusBoxSize);
        readerStatusBox.setMaximumSize(statusBoxSize);
        readerStatusBox.setBorder(new EmptyBorder(8, 12, 8, 12));
        readerStatusBox.setAlignmentX(Component.CENTER_ALIGNMENT);

        readerStatusLabel = new JLabel("", SwingConstants.CENTER);
        readerStatusLabel.setFont(new Font("Segoe UI", Font.BOLD, 12));
        readerStatusBox.add(readerStatusLabel, BorderLayout.CENTER);
        mainPanel.add(readerStatusBox);

        mainPanel.add(Box.createVerticalStrut(12));

        // 5. Waiting hint
        JLabel instructionLabel = new JLabel(
                "<html><div style='text-align: center; width: 290px; color: #8C96A5;'>"
                        + "El diálogo continuará automáticamente hacia el ingreso del PIN al detectar su DNIe."
                        + "</div></html>"
        );
        instructionLabel.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        instructionLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        mainPanel.add(instructionLabel);

        mainPanel.add(Box.createVerticalStrut(16));

        // 6. Cancel Action Button
        JPanel actionPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 12, 0));
        actionPanel.setOpaque(false);
        JButton cancelButton = new JButton("Cancelar");
        cancelButton.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        cancelButton.setFocusable(false);
        cancelButton.putClientProperty(FlatClientProperties.STYLE, "arc: 10");
        cancelButton.addActionListener(e -> settleWithOutcome(CardWaitProvider.WaitOutcome.USER_CANCELLED));
        actionPanel.add(cancelButton);
        actionPanel.setAlignmentX(Component.CENTER_ALIGNMENT);
        mainPanel.add(actionPanel);

        // 7. Countdown Wheel + Label
        if (effectiveTimeout > 0) {
            mainPanel.add(Box.createVerticalStrut(14));
            countdownRow = new DialogUiSupport.CountdownRow(
                    effectiveTimeout,
                    this::checkCardPresenceOnTick,
                    () -> {
                        logger.warn("WaitForCard modal timed out after {}s without DNIe insertion.", effectiveTimeout);
                        settleWithOutcome(CardWaitProvider.WaitOutcome.TIMEOUT);
                    }
            );
            mainPanel.add(countdownRow.getPanel());
        } else {
            countdownRow = null;
        }

        getRootPane().registerKeyboardAction(
                e -> settleWithOutcome(CardWaitProvider.WaitOutcome.USER_CANCELLED),
                KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
                JComponent.WHEN_IN_FOCUSED_WINDOW
        );

        updateReaderStatusBanner(this.readerManager.getStatus());
        this.readerManager.addListener(hardwareListener);
        listenerRegistered.set(true);

        setContentPane(mainPanel);
        pack();
        DialogUiSupport.centerOnActiveScreen(this);

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowOpened(WindowEvent e) {
                updateReaderStatusBanner(WaitForCardDialog.this.readerManager.getStatus());
                if (WaitForCardDialog.this.readerManager.getStatus().cardPresent()) {
                    settleWithOutcome(CardWaitProvider.WaitOutcome.CARD_READY);
                    return;
                }
                if (countdownRow != null && !settled) {
                    countdownRow.start();
                }
                toFront();
                requestFocus();
            }

            @Override
            public void windowClosing(WindowEvent e) {
                settleWithOutcome(CardWaitProvider.WaitOutcome.USER_CANCELLED);
            }

            @Override
            public void windowClosed(WindowEvent e) {
                stopCountdownTimer();
                unregisterHardwareListener();
            }
        });
    }

    private void checkCardPresenceOnTick() {
        if (settled) {
            stopCountdownTimer();
            return;
        }
        if (readerManager.getStatus().cardPresent()) {
            settleWithOutcome(CardWaitProvider.WaitOutcome.CARD_READY);
        }
    }

    private void updateReaderStatusBanner(HardwareStatus status) {
        if (status == null) {
            updateReaderStatusBanner(false, null);
        } else {
            updateReaderStatusBanner(status.readerPresent(), status.readerName());
        }
    }

    private void updateReaderStatusBanner(boolean readerPresent, String readerName) {
        if (readerPresent) {
            String effectiveName = (readerName != null && !readerName.isBlank())
                    ? readerName.trim()
                    : "Dispositivo PC/SC";
            String text = "Lector conectado: " + effectiveName;
            readerStatusLabel.setText("<html><div style='text-align: center; width: 270px;'>"
                    + DialogUiSupport.escapeHtml(text) + "</div></html>");
            readerStatusLabel.setForeground(READER_CONNECTED_COLOR);
            readerStatusBox.putClientProperty(
                    FlatClientProperties.STYLE,
                    "arc: 12; background: darken($Panel.background, 4%); border: 1,1,1,1,#00F5D4,1,12"
            );
        } else {
            readerStatusLabel.setText("<html><div style='text-align: center; width: 270px;'>"
                    + DialogUiSupport.escapeHtml(READER_DISCONNECTED_TEXT) + "</div></html>");
            readerStatusLabel.setForeground(READER_DISCONNECTED_COLOR);
            readerStatusBox.putClientProperty(
                    FlatClientProperties.STYLE,
                    "arc: 12; background: darken($Panel.background, 4%); border: 1,1,1,1,#F59E0B,1,12"
            );
        }
        readerStatusBox.revalidate();
        readerStatusBox.repaint();
    }

    private void stopCountdownTimer() {
        if (countdownRow != null) {
            countdownRow.stop();
        }
    }

    private void unregisterHardwareListener() {
        if (listenerRegistered.compareAndSet(true, false)) {
            readerManager.removeListener(hardwareListener);
        }
    }

    private void settleWithOutcome(CardWaitProvider.WaitOutcome newOutcome) {
        stopCountdownTimer();
        unregisterHardwareListener();
        if (settled) {
            return;
        }
        this.settled = true;
        this.outcome = newOutcome != null ? newOutcome : CardWaitProvider.WaitOutcome.USER_CANCELLED;
        dispose();
    }

    @Override
    public void dispose() {
        stopCountdownTimer();
        unregisterHardwareListener();
        super.dispose();
    }

    /**
     * Asynchronously dismisses the active WaitForCard modal on the Swing EDT for the specified reason.
     */
    public void abortWithReason(CardWaitProvider.WaitOutcome reason) {
        CardWaitProvider.WaitOutcome effectiveReason =
                (reason != null && reason != CardWaitProvider.WaitOutcome.CARD_READY)
                        ? reason
                        : CardWaitProvider.WaitOutcome.USER_CANCELLED;
        SwingUtilities.invokeLater(() -> {
            if (!settled) {
                logger.warn("Aborting active WaitForCard modal (reason={}).", effectiveReason);
                settleWithOutcome(effectiveReason);
            }
        });
    }

    /**
     * Shows the modal dialog (unless a card is already present or aborted) and returns the WaitOutcome.
     */
    public CardWaitProvider.WaitOutcome awaitCard() {
        if (!settled && readerManager.getStatus().cardPresent()) {
            settleWithOutcome(CardWaitProvider.WaitOutcome.CARD_READY);
        }
        if (!settled) {
            setVisible(true);
        }
        return outcome;
    }
}
