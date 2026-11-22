package pe.ong.chasca.killagent.ui;

import org.junit.jupiter.api.Test;

import java.awt.*;
import java.awt.image.BufferedImage;

import static org.junit.jupiter.api.Assertions.*;

class AntiKeyloggerKeypadDialogUiTest {

    @Test
    void testCountdownWheelRendersCleanlyAndTransitionsColorAtTenSeconds() {
        AntiKeyloggerKeypadDialog.CountdownWheelComponent wheel =
                new AntiKeyloggerKeypadDialog.CountdownWheelComponent(30);
        wheel.setSize(48, 48);

        assertEquals(new Color(0, 245, 212), AntiKeyloggerKeypadDialog.resolveCountdownColor(30));
        assertEquals(new Color(0, 245, 212), AntiKeyloggerKeypadDialog.resolveCountdownColor(11));
        assertEquals(new Color(245, 158, 11), AntiKeyloggerKeypadDialog.resolveCountdownColor(10));
        assertEquals(new Color(245, 158, 11), AntiKeyloggerKeypadDialog.resolveCountdownColor(6));
        assertEquals(new Color(247, 37, 133), AntiKeyloggerKeypadDialog.resolveCountdownColor(5));

        BufferedImage img = new BufferedImage(48, 48, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g2 = img.createGraphics();
        try {
            wheel.updateState(25, 25.0 / 30.0, 45.0, false);
            wheel.paint(g2);

            wheel.updateState(10, 10.0 / 30.0, 180.0, false);
            wheel.paint(g2);

            wheel.updateState(0, 0.0, 0.0, true);
            wheel.paint(g2);
        } finally {
            g2.dispose();
        }
    }

    @Test
    void testTrayReadyDescriptionIsNeutral() {
        assertEquals("DNIe listo", TrayIconFactory.TrayState.CARD_READY.getDescription());
        assertFalse(TrayIconFactory.TrayState.CARD_READY.getDescription().toLowerCase().contains("firma"));
    }
}
