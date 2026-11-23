package pe.ong.chasca.killagent.ui;

import com.formdev.flatlaf.FlatDarkLaf;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import pe.ong.chasca.killagent.config.AgentConfig;
import pe.ong.chasca.killagent.hardware.CardReaderManager;
import pe.ong.chasca.killagent.testsupport.MutableTestHardwareProbe;

import javax.swing.*;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class WaitForCardDialogUiTest {

    private static AgentConfig createConfig() {
        return new AgentConfig(
                "production",
                3000,
                "127.0.0.1",
                false,
                "./keystore/loopback.p12",
                "changeit",
                Set.of("http://localhost:5173"),
                "bit4ipki.dll",
                "idplug-pkcs11.dll",
                "dark",
                false
        );
    }

    @Test
    void testWaitForCardDialogClosesAutomaticallyOnCardInsertion() throws Exception {
        Assumptions.assumeFalse(GraphicsEnvironment.isHeadless(), "Swing modal tests require non-headless display");
        FlatDarkLaf.setup();

        MutableTestHardwareProbe probe = new MutableTestHardwareProbe(false);
        probe.removeCard();
        CardReaderManager readerManager = new CardReaderManager(createConfig(), probe);
        readerManager.probeOnce(false);
        assertFalse(readerManager.getStatus().cardPresent());

        AtomicReference<CardWaitProvider.WaitOutcome> outcomeRef = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            WaitForCardDialog dialog = new WaitForCardDialog(
                    null,
                    readerManager,
                    "Inicio de Sesión",
                    "Autenticación Institucional Ch&#39;aska",
                    30
            );
            dialog.addWindowListener(new WindowAdapter() {
                @Override
                public void windowOpened(WindowEvent e) {
                    javax.swing.Timer insertTimer = new javax.swing.Timer(
                            60,
                            evt -> {
                                probe.insertCard();
                                readerManager.probeOnce(true);
                            }
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

        MutableTestHardwareProbe probe = new MutableTestHardwareProbe(false);
        CardReaderManager readerManager = new CardReaderManager(createConfig(), probe);
        readerManager.probeOnce(false);
        assertFalse(readerManager.getStatus().readerPresent());

        AtomicReference<CardWaitProvider.WaitOutcome> outcomeRef = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            WaitForCardDialog dialog = new WaitForCardDialog(
                    null,
                    readerManager,
                    "Inicio de Sesión",
                    "Autenticación Institucional Ch&#39;aska",
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
