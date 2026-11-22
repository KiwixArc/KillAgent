package pe.ong.chasca.killagent.ui;

import javax.swing.*;
import java.awt.*;

/**
 * Shared Swing dialog utilities (branding header, active-screen centering, HTML escaping,
 * and countdown timer panel) reused across KILLAgent hardware security modals.
 */
final class DialogUiSupport {

    private DialogUiSupport() {}

    static JPanel createBrandPanel() {
        ImageIcon shield = AssetManager.getShieldBadge(42);
        ImageIcon logo = AssetManager.getBrandLogo();
        if (shield == null && logo == null) {
            return null;
        }
        JPanel brandPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 0));
        brandPanel.setOpaque(false);
        if (shield != null) {
            brandPanel.add(new JLabel(shield));
        }
        if (logo != null) {
            brandPanel.add(new JLabel(logo));
        }
        brandPanel.setAlignmentX(Component.CENTER_ALIGNMENT);
        return brandPanel;
    }

    static void centerOnActiveScreen(Window window) {
        try {
            Point mouseLoc = MouseInfo.getPointerInfo() != null ? MouseInfo.getPointerInfo().getLocation() : null;
            GraphicsEnvironment ge = GraphicsEnvironment.getLocalGraphicsEnvironment();
            for (GraphicsDevice gd : ge.getScreenDevices()) {
                Rectangle bounds = gd.getDefaultConfiguration().getBounds();
                if (mouseLoc != null && bounds.contains(mouseLoc)) {
                    int x = bounds.x + (bounds.width - window.getWidth()) / 2;
                    int y = bounds.y + (bounds.height - window.getHeight()) / 2;
                    window.setLocation(x, y);
                    return;
                }
            }
        } catch (Exception ignored) {
        }
        window.setLocationRelativeTo(null);
    }

    static String escapeHtml(String input) {
        if (input == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(input.length() + 16);
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            switch (c) {
                case '&' -> sb.append("&amp;");
                case '<' -> sb.append("&lt;");
                case '>' -> sb.append("&gt;");
                case '"' -> sb.append("&quot;");
                case '\'' -> sb.append("&#39;");
                default -> sb.append(c);
            }
        }
        return sb.toString();
    }

    static final class CountdownRow {
        private final JPanel panel;
        private final CountdownWheelComponent wheel;
        private final JLabel label;
        private final int timeoutSeconds;
        private final Runnable preTickCheck;
        private final Runnable onTimeout;
        private final javax.swing.Timer timer;

        private long startNanos = 0L;
        private boolean stopped = false;

        CountdownRow(int timeoutSeconds, Runnable preTickCheck, Runnable onTimeout) {
            this.timeoutSeconds = Math.max(1, timeoutSeconds);
            this.preTickCheck = preTickCheck;
            this.onTimeout = onTimeout;

            this.panel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 0));
            this.panel.setOpaque(false);
            this.panel.setAlignmentX(Component.CENTER_ALIGNMENT);

            this.wheel = new CountdownWheelComponent(this.timeoutSeconds);
            this.label = new JLabel(
                    CountdownWheelComponent.formatCountdownText(this.timeoutSeconds),
                    SwingConstants.LEFT
            );
            this.label.setFont(new Font("Segoe UI", Font.PLAIN, 11));
            this.label.setForeground(CountdownWheelComponent.DEFAULT_COUNTDOWN_LABEL_COLOR);

            this.panel.add(this.wheel);
            this.panel.add(this.label);
            this.panel.setMaximumSize(this.panel.getPreferredSize());

            this.timer = new javax.swing.Timer(100, e -> onTick());
            this.timer.setRepeats(true);
        }

        JPanel getPanel() {
            return panel;
        }

        void start() {
            if (!stopped) {
                startNanos = System.nanoTime();
                timer.start();
            }
        }

        void stop() {
            stopped = true;
            timer.stop();
        }

        private void onTick() {
            if (stopped) {
                timer.stop();
                return;
            }
            if (preTickCheck != null) {
                preTickCheck.run();
                if (stopped) {
                    return;
                }
            }
            if (startNanos == 0L) {
                startNanos = System.nanoTime();
            }

            long elapsedMillis = Math.max(0L, (System.nanoTime() - startNanos) / 1_000_000L);
            long totalMillis = timeoutSeconds * 1000L;
            long remainingMillis = Math.max(0L, totalMillis - elapsedMillis);

            double progressFraction = totalMillis > 0L ? (double) remainingMillis / (double) totalMillis : 0.0;
            int computedRemaining = (int) Math.ceil(remainingMillis / 1000.0);
            double spinnerAngleDeg = (90.0 - (elapsedMillis * 360.0 / 2000.0)) % 360.0;

            wheel.updateState(computedRemaining, progressFraction, spinnerAngleDeg, remainingMillis <= 0L);

            String nextText = CountdownWheelComponent.formatCountdownText(computedRemaining);
            if (!nextText.equals(label.getText())) {
                label.setText(nextText);
            }
            label.setForeground(CountdownWheelComponent.resolveCountdownLabelColor(computedRemaining));

            if (remainingMillis <= 0L) {
                stop();
                if (onTimeout != null) {
                    onTimeout.run();
                }
            }
        }
    }
}
