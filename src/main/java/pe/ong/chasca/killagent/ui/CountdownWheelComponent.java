package pe.ong.chasca.killagent.ui;

import javax.swing.*;
import java.awt.*;
import java.awt.geom.Arc2D;
import java.awt.geom.Ellipse2D;

/**
 * Custom anti-aliased Swing component rendering a live circular countdown loading wheel
 * with track ring, remaining-time progress arc, rotating sweep indicator, and centered "${remainingSeconds}s" text.
 */
public class CountdownWheelComponent extends JComponent {

    static final Color NORMAL_COUNTDOWN_COLOR = new Color(0, 245, 212);   // Ch'aska Mint (#00F5D4)
    static final Color WARNING_COUNTDOWN_COLOR = new Color(245, 158, 11); // Amber (#F59E0B)
    static final Color CRITICAL_COUNTDOWN_COLOR = new Color(247, 37, 133);// Neon Magenta (#F72585)
    static final Color DEFAULT_COUNTDOWN_LABEL_COLOR = new Color(140, 150, 165);

    private static final int WHEEL_SIZE = 48;
    private static final Color TRACK_RING_COLOR = new Color(130, 140, 160, 75);

    private int displaySeconds;
    private double progressFraction;
    private double spinnerAngleDeg;
    private boolean stopped;

    public CountdownWheelComponent(int initialSeconds) {
        this.displaySeconds = Math.max(0, initialSeconds);
        this.progressFraction = initialSeconds > 0 ? 1.0 : 0.0;
        this.spinnerAngleDeg = 90.0;
        this.stopped = false;
        setOpaque(false);
        Dimension size = new Dimension(WHEEL_SIZE, WHEEL_SIZE);
        setPreferredSize(size);
        setMinimumSize(size);
        setMaximumSize(size);
    }

    public static Color resolveCountdownColor(int remainingSeconds) {
        if (remainingSeconds <= 5) {
            return CRITICAL_COUNTDOWN_COLOR;
        }
        if (remainingSeconds <= 10) {
            return WARNING_COUNTDOWN_COLOR;
        }
        return NORMAL_COUNTDOWN_COLOR;
    }

    static Color resolveCountdownLabelColor(int remainingSeconds) {
        if (remainingSeconds <= 5) {
            return CRITICAL_COUNTDOWN_COLOR;
        }
        if (remainingSeconds <= 10) {
            return WARNING_COUNTDOWN_COLOR;
        }
        return DEFAULT_COUNTDOWN_LABEL_COLOR;
    }

    static String formatCountdownText(int seconds) {
        return "Tiempo límite: " + Math.max(0, seconds) + "s";
    }

    public void updateState(int remainingSeconds, double progressFraction, double spinnerAngleDeg, boolean stopped) {
        this.displaySeconds = Math.max(0, remainingSeconds);
        this.progressFraction = Math.max(0.0, Math.min(1.0, progressFraction));
        this.spinnerAngleDeg = spinnerAngleDeg;
        this.stopped = stopped;
        repaint();
    }

    @Override
    protected void paintComponent(Graphics g) {
        super.paintComponent(g);
        Graphics2D g2 = (Graphics2D) g.create();
        try {
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setRenderingHint(RenderingHints.KEY_STROKE_CONTROL, RenderingHints.VALUE_STROKE_PURE);
            g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);

            int w = getWidth() > 0 ? getWidth() : WHEEL_SIZE;
            int h = getHeight() > 0 ? getHeight() : WHEEL_SIZE;
            int size = Math.min(w, h);
            float strokeWidth = 3.5f;
            float pad = strokeWidth / 2.0f + 3.0f;
            float arcSize = Math.max(8.0f, size - 2.0f * pad);
            float x = (w - arcSize) / 2.0f;
            float y = (h - arcSize) / 2.0f;

            // 1. Subtle track ring
            g2.setStroke(new BasicStroke(strokeWidth, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
            g2.setColor(TRACK_RING_COLOR);
            g2.draw(new Arc2D.Float(x, y, arcSize, arcSize, 0.0f, 360.0f, Arc2D.OPEN));

            Color accentColor = resolveCountdownColor(displaySeconds);

            // 2. Remaining time progress arc (clockwise from 12 o'clock)
            if (progressFraction > 0.0) {
                float extent = (float) (-360.0 * progressFraction);
                g2.setColor(accentColor);
                g2.draw(new Arc2D.Float(x, y, arcSize, arcSize, 90.0f, extent, Arc2D.OPEN));
            }

            // 3. Rotating sweep highlight & orbiting indicator dot
            if (!stopped && progressFraction > 0.0) {
                g2.setStroke(new BasicStroke(strokeWidth + 0.4f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
                g2.setColor(new Color(255, 255, 255, 130));
                g2.draw(new Arc2D.Float(x, y, arcSize, arcSize, (float) spinnerAngleDeg, 42.0f, Arc2D.OPEN));

                double rad = Math.toRadians(spinnerAngleDeg);
                double radius = arcSize / 2.0;
                double cx = x + radius;
                double cy = y + radius;
                double dotX = cx + radius * Math.cos(rad);
                double dotY = cy - radius * Math.sin(rad);
                double dotRadius = 2.4;
                g2.setColor(Color.WHITE);
                g2.fill(new Ellipse2D.Double(dotX - dotRadius, dotY - dotRadius, dotRadius * 2.0, dotRadius * 2.0));
            }

            // 4. Centered countdown text "${remainingSeconds}s"
            String label = displaySeconds + "s";
            g2.setFont(new Font("Segoe UI", Font.BOLD, 11));
            FontMetrics fm = g2.getFontMetrics();
            int textX = (w - fm.stringWidth(label)) / 2;
            int textY = ((h - fm.getHeight()) / 2) + fm.getAscent();
            g2.setColor(accentColor);
            g2.drawString(label, textX, textY);
        } finally {
            g2.dispose();
        }
    }
}
