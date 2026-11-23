package pe.ong.chasca.killagent.ui;

import java.awt.*;
import java.awt.geom.Ellipse2D;
import java.awt.geom.RoundRectangle2D;
import java.awt.image.BufferedImage;

/**
 * Creates dynamic, high-DPI Windows system tray icons reflecting agent health states:
 * - GRAY: Daemon running, but no smart card reader detected.
 * - ORANGE: Reader connected, but no DNIe card inserted.
 * - GREEN: DNIe inserted and ready.
 * - BLUE: Cryptographic operation / PIN prompt in progress.
 */
public final class TrayIconFactory {

    public enum TrayState {
        NO_READER(new Color(120, 120, 120), "Sin lector detectado"),
        NO_CARD(new Color(245, 140, 20), "Lector conectado, inserte DNIe"),
        CARD_READY(new Color(40, 167, 69), "DNIe listo"),
        BUSY_SIGNING(new Color(0, 123, 255), "Operación criptográfica en curso");

        private final Color color;
        private final String description;

        TrayState(Color color, String description) {
            this.color = color;
            this.description = description;
        }

        public Color getColor() {
            return color;
        }

        public String getDescription() {
            return description;
        }
    }

    private TrayIconFactory() {
    }

    public static Image createIcon(TrayState state) {
        int size = 32; // Crisp on high-DPI Windows displays
        BufferedImage image = new BufferedImage(size, size, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = image.createGraphics();

        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);

        // Draw modern shield base
        g.setColor(new Color(30, 30, 35));
        g.fill(new RoundRectangle2D.Float(2, 2, size - 4, size - 4, 8, 8));

        // Draw outer accent border
        g.setColor(new Color(60, 60, 70));
        g.setStroke(new BasicStroke(1.5f));
        g.draw(new RoundRectangle2D.Float(2, 2, size - 4, size - 4, 8, 8));

        // Draw status indicator circle
        g.setColor(state.getColor());
        int indicatorSize = 12;
        int offset = (size - indicatorSize) / 2;
        g.fill(new Ellipse2D.Float(offset, offset, indicatorSize, indicatorSize));

        g.dispose();
        return image;
    }
}
