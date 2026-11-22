package pe.ong.chasca.killagent.ui;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pe.ong.chasca.killagent.hardware.CardReaderManager;

import javax.swing.*;
import java.awt.GraphicsEnvironment;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Production Swing implementation of {@link CardWaitProvider} ensuring EDT-safe modal execution
 * via {@link WaitForCardDialog} and thread-safe asynchronous cancellation upon client disconnect
 * or explicit user cancel.
 */
public class SwingCardWaitProvider implements CardWaitProvider {

    private static final Logger logger = LoggerFactory.getLogger(SwingCardWaitProvider.class);

    private final AtomicReference<WaitForCardDialog> activeDialogRef = new AtomicReference<>();
    private final Object waitLifecycleLock = new Object();
    private boolean awaitingDialogCreation = false;
    private WaitOutcome preCreationAbortReason = null;

    @Override
    public WaitOutcome waitForCard(
            CardReaderManager readerManager,
            String title,
            String operationHtmlDetails,
            int timeoutSeconds
    ) {
        if (readerManager != null && readerManager.getStatus().cardPresent()) {
            return WaitOutcome.CARD_READY;
        }
        if (GraphicsEnvironment.isHeadless()) {
            logger.warn("Headless graphics environment detected; rejecting interactive WaitForCard modal.");
            return WaitOutcome.USER_CANCELLED;
        }

        final AtomicReference<WaitOutcome> resultHolder = new AtomicReference<>(WaitOutcome.USER_CANCELLED);

        synchronized (waitLifecycleLock) {
            preCreationAbortReason = null;
            awaitingDialogCreation = true;
        }

        Runnable showTask = () -> {
            WaitForCardDialog dialog;
            synchronized (waitLifecycleLock) {
                awaitingDialogCreation = false;
                if (preCreationAbortReason != null) {
                    resultHolder.set(preCreationAbortReason);
                    preCreationAbortReason = null;
                    return;
                }
                if (readerManager != null && readerManager.getStatus().cardPresent()) {
                    resultHolder.set(WaitOutcome.CARD_READY);
                    return;
                }
                dialog = new WaitForCardDialog(null, readerManager, title, operationHtmlDetails, timeoutSeconds);
                activeDialogRef.set(dialog);
            }
            try {
                resultHolder.set(dialog.awaitCard());
            } finally {
                activeDialogRef.compareAndSet(dialog, null);
            }
        };

        try {
            if (SwingUtilities.isEventDispatchThread()) {
                showTask.run();
            } else {
                SwingUtilities.invokeAndWait(showTask);
            }
        } catch (Exception e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            logger.error("Interrupted while waiting for smart card insertion modal: {}", e.getMessage(), e);
            abortActiveWait(WaitOutcome.USER_CANCELLED);
        } finally {
            synchronized (waitLifecycleLock) {
                awaitingDialogCreation = false;
                preCreationAbortReason = null;
            }
        }

        return resultHolder.get();
    }

    @Override
    public void abortActiveWait(WaitOutcome reason) {
        WaitOutcome effectiveReason = (reason != null && reason != WaitOutcome.CARD_READY)
                ? reason
                : WaitOutcome.USER_CANCELLED;
        WaitForCardDialog active;
        synchronized (waitLifecycleLock) {
            if (awaitingDialogCreation && preCreationAbortReason == null) {
                preCreationAbortReason = effectiveReason;
            }
            active = activeDialogRef.getAndSet(null);
        }
        if (active != null) {
            active.abortWithReason(effectiveReason);
        }
    }
}
