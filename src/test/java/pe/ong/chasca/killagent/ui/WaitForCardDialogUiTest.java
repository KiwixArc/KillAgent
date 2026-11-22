package pe.ong.chasca.killagent.ui;

import com.formdev.flatlaf.FlatDarkLaf;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import pe.ong.chasca.killagent.config.AgentConfig;
import pe.ong.chasca.killagent.hardware.CardReaderManager;

import javax.swing.*;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class WaitForCardDialogUiTest {

    private static AgentConfig createConfig(boolean mockEnabled) {
        return new AgentConfig(
                "development",
                3000,
                "127.0.0.1",
                false,
                "./keystore/loopback.p12",
                "changeit",
                Set.of("http://localhost:5173"),
                "bit4ipki.dll",
                "idplug-pkcs11.dll",
                mockEnabled,
                "71234567",
                "JUAN PEREZ GARCIA",
                "dark",
                false
        );
    }

    @Test
    void testWaitForCardDialogClosesAutomaticallyOnCardInsertion() throws Exception {
        Assumptions.assumeFalse(GraphicsEnvironment.isHeadless(), "Swing modal tests require non-headless display");
        FlatDarkLaf.setup();

        CardReaderManager readerManager = new CardReaderManager(createConfig(true));
        readerManager.simulateMockCardRemoval();
        assertFalse(readerManager.getStatus().cardPresent());

        AtomicReference<CardWaitProvider.WaitOutcome> outcomeRef = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            WaitForCardDialog dialog = new WaitForCardDialog(
                    null,
                    readerManager,
                    "Inicio de Sesión",
                    "Autenticación Institucional Ch&#39;asca",
                    30
            );
            dialog.addWindowListener(new WindowAdapter() {
                @Override
                public void windowOpened(WindowEvent e) {
                    javax.swing.Timer insertTimer = new javax.swing.Timer(
                            60,
                            evt -> readerManager.simulateMockCardInsertion()
                    );
                    insertTimer.setRepeats(false);
                    insertTimer.start();
                }
            });
            outcomeRef.set(dialog.awaitCard());
        });

        assertEquals(CardWaitProvider.WaitOutcome.CARD_READY, outcomeRef.get());
        assertTrue(readerManager.getStatus().cardPresent());
    }

    @Test
    void testWaitForCardDialogShowsDisconnectedReaderAndAbortsOnCancel() throws Exception {
        Assumptions.assumeFalse(GraphicsEnvironment.isHeadless(), "Swing modal tests require non-headless display");
        FlatDarkLaf.setup();

        CardReaderManager readerManager = new CardReaderManager(createConfig(false));
        assertFalse(readerManager.getStatus().readerPresent());

        AtomicReference<CardWaitProvider.WaitOutcome> outcomeRef = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            WaitForCardDialog dialog = new WaitForCardDialog(
                    null,
                    readerManager,
                    "Inicio de Sesión",
                    "Autenticación Institucional Ch&#39;asca",
                    30
            );
            dialog.addWindowListener(new WindowAdapter() {
                @Override
                public void windowOpened(WindowEvent e) {
                    javax.swing.Timer abortTimer = new javax.swing.Timer(
                            60,
                            evt -> dialog.abortWithReason(CardWaitProvider.WaitOutcome.USER_CANCELLED)
                    );
                    abortTimer.setRepeats(false);
                    abortTimer.start();
                }
            });
            outcomeRef.set(dialog.awaitCard());
        });

        assertEquals(CardWaitProvider.WaitOutcome.USER_CANCELLED, outcomeRef.get());
    }
}
