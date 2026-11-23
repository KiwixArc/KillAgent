package pe.ong.chasca.killagent.ui;

import com.formdev.flatlaf.FlatClientProperties;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.WinDef.HWND;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Zero Trust Anti-Keylogger PIN modal featuring:
 * - Zero-String Memory Architecture: PIN digits exist solely inside a pre-allocated char[] buffer
 *   and never touch java.lang.String, JTextComponent Documents, or system clipboards.
 * - Cryptographically shuffled on-screen numeric keypad (SecureRandom per session).
 * - Optional physical keyboard lockout toggle (mouse-only anti-keylogger mode).
 * - Kernel-level Windows anti-screen-scraping via SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE / WDA_MONITOR).
 * - Instant Kill-Switch dismissal and buffer zeroization upon physical card removal.
 */
public class AntiKeyloggerKeypadDialog extends JDialog {

    private static final Logger logger = LoggerFactory.getLogger(AntiKeyloggerKeypadDialog.class);
    public static final int DEFAULT_TIMEOUT_SECONDS = 30;
    private static final int MAX_PIN_LENGTH = 8;
    private static final int MIN_PIN_LENGTH = 4;
    private static final int WDA_MONITOR = 0x00000001;
    private static final int WDA_EXCLUDEFROMCAPTURE = 0x00000011;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Static mask strings containing ONLY bullet symbols — zero secret PIN characters ever enter String memory.
     */
    private static final String[] BULLET_MASKS = {
            "",
            "●",
            "●  ●",
            "●  ●  ●",
            "●  ●  ●  ●",
            "●  ●  ●  ●  ●",
            "●  ●  ●  ●  ●  ●",
            "●  ●  ●  ●  ●  ●  ●",
            "●  ●  ●  ●  ●  ●  ●  ●"
    };

    private final char[] secretBuffer = new char[MAX_PIN_LENGTH];
    private int currentLength = 0;

    private final JLabel pinMaskLabel;
    private final JButton okButton;
    private final JCheckBox mouseOnlyCheckBox;
    private final int timeoutSeconds;
    private final DialogUiSupport.CountdownRow countdownRow;
    private KeyEventDispatcher keyDispatcher;

    private char[] deliveredPin = null;
    private PinPromptProvider.AbortReason abortReason = PinPromptProvider.AbortReason.USER_CANCELLED;
    private boolean settled = false;

    public AntiKeyloggerKeypadDialog(Frame parent, String title, String operationDetails) {
        this(parent, title, operationDetails, DEFAULT_TIMEOUT_SECONDS);
    }

    public AntiKeyloggerKeypadDialog(Frame parent, String title, String operationDetails, int timeoutSeconds) {
        super(parent, title, true);
        this.timeoutSeconds = Math.max(0, timeoutSeconds);
        setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);
        setAlwaysOnTop(true);
        setResizable(false);
        setIconImage(AssetManager.getAppIcon());

        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        mainPanel.setBorder(new EmptyBorder(20, 26, 20, 26));

        // 1. Top Branding Row (Zero Trust Shield Badge + Ch'aska Wordmark)
        JPanel brandPanel = DialogUiSupport.createBrandPanel();
        if (brandPanel != null) {
            mainPanel.add(brandPanel);
            mainPanel.add(Box.createVerticalStrut(10));
        }

        // 2. Operation Title Header
        String effectiveHeader = (title != null && !title.isBlank())
                ? title.trim()
                : "Autorización Criptográfica DNIe";
        JLabel headerLabel = new JLabel("<html><div style='text-align: center; width: 280px; color: #00F5D4;'>"
                + DialogUiSupport.escapeHtml(effectiveHeader) + "</div></html>");
        headerLabel.setFont(new Font("Segoe UI", Font.BOLD, 15));
        headerLabel.setForeground(pe.ong.chasca.killagent.ui.CountdownWheelComponent.NORMAL_COUNTDOWN_COLOR);
        headerLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        mainPanel.add(headerLabel);

        mainPanel.add(Box.createVerticalStrut(6));

        // 3. Operation Context Details (Auth Challenge or Document Title + SHA-256 Preview + Role)
        JLabel detailLabel = new JLabel("<html><div style='text-align: center; width: 280px; color: #B8C2CC;'>"
                + operationDetails + "</div></html>");
        detailLabel.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        detailLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        mainPanel.add(detailLabel);

        mainPanel.add(Box.createVerticalStrut(14));

        // 4. Zero-String PIN Mask Display Box (No JPasswordField / No Clipboard / No TransferHandler)
        JPanel pinDisplayBox = new JPanel(new BorderLayout());
        pinDisplayBox.setMaximumSize(new Dimension(240, 42));
        pinDisplayBox.setPreferredSize(new Dimension(240, 42));
        pinDisplayBox.putClientProperty(
                FlatClientProperties.STYLE,
                "arc: 12; background: darken($Panel.background, 4%); border: 1,1,1,1,#7209B7,1,12"
        );

        pinMaskLabel = new JLabel("Ingrese su PIN (4-8 dígitos)", SwingConstants.CENTER);
        pinMaskLabel.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        pinMaskLabel.setForeground(new Color(140, 150, 165));
        pinMaskLabel.setTransferHandler(null);
        pinDisplayBox.add(pinMaskLabel, BorderLayout.CENTER);

        pinDisplayBox.setAlignmentX(Component.CENTER_ALIGNMENT);
        mainPanel.add(pinDisplayBox);

        mainPanel.add(Box.createVerticalStrut(14));

        // 5. Cryptographically Scrambled Virtual Keypad
        JPanel keypadPanel = createScrambledKeypad();
        keypadPanel.setAlignmentX(Component.CENTER_ALIGNMENT);
        mainPanel.add(keypadPanel);

        mainPanel.add(Box.createVerticalStrut(10));

        // 6. Optional Physical Keyboard Lockout Checkbox
        mouseOnlyCheckBox = new JCheckBox("Solo clics de mouse (bloquear teclado físico)", false);
        mouseOnlyCheckBox.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        mouseOnlyCheckBox.setFocusable(false);
        mouseOnlyCheckBox.setAlignmentX(Component.CENTER_ALIGNMENT);
        mainPanel.add(mouseOnlyCheckBox);

        mainPanel.add(Box.createVerticalStrut(14));

        // 7. Action Buttons (Cancel / Confirm)
        JPanel actionPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 12, 0));
        JButton cancelButton = new JButton("Cancelar");
        cancelButton.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        cancelButton.setFocusable(false);
        cancelButton.putClientProperty(FlatClientProperties.STYLE, "arc: 10");
        cancelButton.addActionListener(e -> cancelAndSanitize(PinPromptProvider.AbortReason.USER_CANCELLED));

        okButton = new JButton("Confirmar PIN");
        okButton.setFont(new Font("Segoe UI", Font.BOLD, 13));
        okButton.setBackground(new Color(114, 9, 183)); // Ch'aska Cosmic Purple (#7209B7)
        okButton.setForeground(Color.WHITE);
        okButton.setEnabled(false);
        okButton.setFocusable(false);
        okButton.putClientProperty(FlatClientProperties.STYLE, "arc: 10; borderColor: #00F5D4");
        okButton.addActionListener(e -> confirmAndExtract());

        actionPanel.add(cancelButton);
        actionPanel.add(okButton);
        mainPanel.add(actionPanel);

        if (this.timeoutSeconds > 0) {
            mainPanel.add(Box.createVerticalStrut(12));
            countdownRow = new DialogUiSupport.CountdownRow(
                    this.timeoutSeconds,
                    () -> {
                        if (settled) {
                            stopCountdownTimer();
                        }
                    },
                    () -> {
                        logger.warn("PIN prompt timed out after {}s; sanitizing PIN buffer and dismissing dialog.", this.timeoutSeconds);
                        cancelAndSanitize(PinPromptProvider.AbortReason.TIMEOUT);
                    }
            );
            mainPanel.add(countdownRow.getPanel());
        } else {
            countdownRow = null;
        }

        setContentPane(mainPanel);
        pack();
        DialogUiSupport.centerOnActiveScreen(this);

        // Lifecycle hooks: apply Windows Anti-Capture when native HWND materializes & sanitize on close
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowOpened(WindowEvent e) {
                applyAntiScreenCapture();
                installPhysicalKeyInterceptor();
                if (countdownRow != null && !settled) {
                    countdownRow.start();
                }
                toFront();
                requestFocus();
            }

            @Override
            public void windowClosing(WindowEvent e) {
                cancelAndSanitize(PinPromptProvider.AbortReason.USER_CANCELLED);
            }

            @Override
            public void windowClosed(WindowEvent e) {
                stopCountdownTimer();
                uninstallPhysicalKeyInterceptor();
                Arrays.fill(secretBuffer, '\0');
                currentLength = 0;
            }
        });
    }

    private JPanel createScrambledKeypad() {
        JPanel keypad = new JPanel(new GridLayout(4, 3, 8, 8));
        keypad.setMaximumSize(new Dimension(240, 192));

        List<Integer> digits = new ArrayList<>(List.of(0, 1, 2, 3, 4, 5, 6, 7, 8, 9));
        Collections.shuffle(digits, SECURE_RANDOM);

        for (int i = 0; i < 9; i++) {
            keypad.add(createNumberButton(digits.get(i)));
        }

        // Row 4: [Clear 'C'] [10th Shuffled Digit] [Backspace '←']
        JButton clearBtn = new JButton("C");
        clearBtn.setFont(new Font("Segoe UI", Font.BOLD, 13));
        clearBtn.setForeground(new Color(247, 37, 133)); // Neon Magenta (#F72585)
        clearBtn.setFocusable(false);
        clearBtn.setToolTipText("Limpiar PIN");
        clearBtn.putClientProperty(FlatClientProperties.STYLE, "arc: 12");
        clearBtn.addActionListener(e -> clearDigits());
        keypad.add(clearBtn);

        keypad.add(createNumberButton(digits.get(9)));

        JButton backspaceBtn = new JButton("←");
        backspaceBtn.setFont(new Font("Segoe UI", Font.BOLD, 15));
        backspaceBtn.setForeground(new Color(0, 229, 255)); // Neon Cyan (#00E5FF)
        backspaceBtn.setFocusable(false);
        backspaceBtn.setToolTipText("Borrar último dígito");
        backspaceBtn.putClientProperty(FlatClientProperties.STYLE, "arc: 12");
        backspaceBtn.addActionListener(e -> deleteLastDigit());
        keypad.add(backspaceBtn);

        return keypad;
    }

    private JButton createNumberButton(int digit) {
        char digitChar = (char) ('0' + digit);
        JButton btn = new JButton(String.valueOf(digit));
        btn.setFont(new Font("Segoe UI", Font.BOLD, 16));
        btn.setFocusable(false);
        btn.setPreferredSize(new Dimension(56, 42));
        btn.putClientProperty(FlatClientProperties.STYLE, "arc: 12");
        btn.addActionListener(e -> appendDigit(digitChar));
        return btn;
    }

    private void appendDigit(char digitChar) {
        if (digitChar >= '0' && digitChar <= '9' && currentLength < MAX_PIN_LENGTH) {
            secretBuffer[currentLength++] = digitChar;
            refreshMaskDisplay();
        }
    }

    private void deleteLastDigit() {
        if (currentLength > 0) {
            secretBuffer[--currentLength] = '\0';
            refreshMaskDisplay();
        }
    }

    private void clearDigits() {
        Arrays.fill(secretBuffer, '\0');
        currentLength = 0;
        refreshMaskDisplay();
    }

    private void refreshMaskDisplay() {
        if (currentLength == 0) {
            pinMaskLabel.setFont(new Font("Segoe UI", Font.PLAIN, 13));
            pinMaskLabel.setForeground(new Color(140, 150, 165));
            pinMaskLabel.setText("Ingrese su PIN (4-8 dígitos)");
        } else {
            pinMaskLabel.setFont(new Font("Segoe UI", Font.BOLD, 18));
            pinMaskLabel.setForeground(new Color(0, 245, 212));
            pinMaskLabel.setText(BULLET_MASKS[currentLength]);
        }
        okButton.setEnabled(currentLength >= MIN_PIN_LENGTH);
    }

    private void installPhysicalKeyInterceptor() {
        keyDispatcher = e -> {
            if (!isShowing() || e.getID() != KeyEvent.KEY_PRESSED) {
                return false;
            }
            // Block any Ctrl/Alt/Meta clipboard shortcuts unconditionally
            if (e.isControlDown() || e.isMetaDown() || e.isAltDown()) {
                e.consume();
                return true;
            }

            int code = e.getKeyCode();
            if (code == KeyEvent.VK_ESCAPE) {
                e.consume();
                cancelAndSanitize(PinPromptProvider.AbortReason.USER_CANCELLED);
                return true;
            }
            if (code == KeyEvent.VK_ENTER) {
                e.consume();
                if (currentLength >= MIN_PIN_LENGTH) {
                    confirmAndExtract();
                }
                return true;
            }

            // If user opted for strict mouse-only mode, discard all physical typing
            if (mouseOnlyCheckBox.isSelected()) {
                e.consume();
                return true;
            }

            if (code == KeyEvent.VK_BACK_SPACE || code == KeyEvent.VK_DELETE) {
                e.consume();
                deleteLastDigit();
                return true;
            }

            char ch = e.getKeyChar();
            if (ch >= '0' && ch <= '9') {
                e.consume();
                appendDigit(ch);
                return true;
            }
            return false;
        };
        KeyboardFocusManager.getCurrentKeyboardFocusManager().addKeyEventDispatcher(keyDispatcher);
    }

    private void uninstallPhysicalKeyInterceptor() {
        if (keyDispatcher != null) {
            KeyboardFocusManager.getCurrentKeyboardFocusManager().removeKeyEventDispatcher(keyDispatcher);
            keyDispatcher = null;
        }
    }

    private void stopCountdownTimer() {
        if (countdownRow != null) {
            countdownRow.stop();
        }
    }

    static Color resolveCountdownColor(int remainingSeconds) {
        return pe.ong.chasca.killagent.ui.CountdownWheelComponent.resolveCountdownColor(remainingSeconds);
    }

    static final class CountdownWheelComponent extends pe.ong.chasca.killagent.ui.CountdownWheelComponent {
        CountdownWheelComponent(int initialSeconds) {
            super(initialSeconds);
        }
    }

    private void confirmAndExtract() {
        if (settled || currentLength < MIN_PIN_LENGTH) {
            return;
        }
        stopCountdownTimer();
        this.settled = true;
        this.deliveredPin = Arrays.copyOf(secretBuffer, currentLength);
        this.abortReason = PinPromptProvider.AbortReason.NONE;
        Arrays.fill(secretBuffer, '\0');
        currentLength = 0;
        dispose();
    }

    private void cancelAndSanitize(PinPromptProvider.AbortReason reason) {
        stopCountdownTimer();
        if (settled) {
            return;
        }
        this.settled = true;
        this.abortReason = reason != null ? reason : PinPromptProvider.AbortReason.USER_CANCELLED;
        Arrays.fill(secretBuffer, '\0');
        currentLength = 0;
        if (deliveredPin != null) {
            Arrays.fill(deliveredPin, '\0');
            deliveredPin = null;
        }
        dispose();
    }

    @Override
    public void dispose() {
        stopCountdownTimer();
        super.dispose();
    }

    /**
     * Asynchronously dismisses and sanitizes the active PIN modal on the Swing EDT
     * for the given abort reason (e.g., card removal or client WebSocket disconnect).
     */
    public void abortWithReason(PinPromptProvider.AbortReason reason) {
        PinPromptProvider.AbortReason effectiveReason =
                reason != null ? reason : PinPromptProvider.AbortReason.USER_CANCELLED;
        SwingUtilities.invokeLater(() -> {
            if (!settled && isDisplayable()) {
                logger.warn("Aborting active PIN modal (reason={}). Sanitizing PIN buffer and dismissing dialog.",
                        effectiveReason);
                cancelAndSanitize(effectiveReason);
            }
        });
    }

    /**
     * Invoked immediately by the hardware Kill-Switch if the smart card is physically pulled out
     * while the user is looking at the PIN modal.
     */
    public void abortDueToCardRemoval() {
        abortWithReason(PinPromptProvider.AbortReason.CARD_REMOVED);
    }

    private void applyAntiScreenCapture() {
        try {
            long windowHandle = Native.getWindowID(this);
            if (windowHandle == 0L) {
                return;
            }
            HWND hwnd = new HWND(new Pointer(windowHandle));
            // Try Windows 10 2004+ / Windows 11 full exclusion first; fallback to WDA_MONITOR black-box
            boolean excluded = WindowsUser32.INSTANCE.SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE);
            if (excluded) {
                logger.debug("Applied Windows anti-capture display affinity (WDA_EXCLUDEFROMCAPTURE).");
            } else if (WindowsUser32.INSTANCE.SetWindowDisplayAffinity(hwnd, WDA_MONITOR)) {
                logger.debug("Applied Windows anti-capture display affinity (WDA_MONITOR).");
            }
        } catch (Throwable t) {
            logger.debug("Windows SetWindowDisplayAffinity unavailable in current environment: {}", t.getMessage());
        }
    }

    /**
     * Shows the modal dialog and returns the structured PinPromptResult.
     */
    public PinPromptProvider.PinPromptResult promptPinResult() {
        if (!settled) {
            setVisible(true);
        }
        return new PinPromptProvider.PinPromptResult(deliveredPin, abortReason);
    }

    /**
     * Convenience method returning the captured char[] PIN, or null if cancelled/aborted.
     */
    public char[] promptPin() {
        PinPromptProvider.PinPromptResult res = promptPinResult();
        return res.isConfirmed() ? res.pin() : null;
    }

    private interface WindowsUser32 extends com.sun.jna.platform.win32.User32 {
        WindowsUser32 INSTANCE = Native.load("user32", WindowsUser32.class);
        boolean SetWindowDisplayAffinity(HWND hWnd, int dwAffinity);
    }
}
