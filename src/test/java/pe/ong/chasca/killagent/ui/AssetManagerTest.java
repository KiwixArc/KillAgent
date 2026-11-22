package pe.ong.chasca.killagent.ui;

import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.awt.*;

import static org.junit.jupiter.api.Assertions.*;

class AssetManagerTest {

    @Test
    void testAllTrayStateSvgIconsLoadAndRender() {
        for (TrayIconFactory.TrayState state : TrayIconFactory.TrayState.values()) {
            Image icon = AssetManager.getTrayIcon(state);
            assertNotNull(icon, "Icon for state " + state + " should not be null");
            assertEquals(32, icon.getWidth(null));
            assertEquals(32, icon.getHeight(null));
        }
    }

    @Test
    void testAppIconAndShieldBadgeSvgRender() {
        Image appIcon = AssetManager.getAppIcon();
        assertNotNull(appIcon);
        assertEquals(64, appIcon.getWidth(null));
        assertEquals(64, appIcon.getHeight(null));

        ImageIcon shieldBadge = AssetManager.getShieldBadge(64);
        assertNotNull(shieldBadge);
        assertEquals(64, shieldBadge.getIconWidth());
        assertEquals(64, shieldBadge.getIconHeight());

        ImageIcon brandLogo = AssetManager.getBrandLogo();
        assertNotNull(brandLogo);
        assertTrue(brandLogo.getIconWidth() > 0);
    }
}

