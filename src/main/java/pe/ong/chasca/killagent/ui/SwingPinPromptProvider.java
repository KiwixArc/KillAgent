package pe.ong.chasca.killagent.ui;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import java.awt.GraphicsEnvironment;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Production Swing implementation of {@link PinPromptProvider} ensuring EDT-safe modal execution
 * and thread-safe asynchronous cancellation upon physical card removal (Kill-Switch), timeout,
 * or client disconnection.
 */
public class SwingPinPromptProvider implements PinPromptProvider {

    private static final Logger logger = LoggerFactory.getLogger(SwingPinPromptProvider.class);

    private final AtomicReference<AntiKeyloggerKeypadDialog> activeDialogRef = new AtomicReference<>();
    private final Object promptLifecycleLock = new Object();
    private boolean awaitingDialogCreation = false;
    private AbortReason preCreationAbortReason = null;

    @Override
    public PinPromptResult requestPin(String title, String operationHtmlDetails) {
        return requestPin(title, operationHtmlDetails, AntiKeyloggerKeypadDialog.DEFAULT_TIMEOUT_SECONDS);
    }

    @Override
    public PinPromptResult requestPin(String title, String operationHtmlDetails, int timeoutSeconds) {
        if (GraphicsEnvironment.isHeadless()) {
            logger.warn("Headless graphics environment detected; rejecting interactive PIN prompt.");
            return new PinPromptResult(null, AbortReason.USER_CANCELLED);
        }

        final AtomicReference<PinPromptResult> resultHolder = new AtomicReference<>(
                new PinPromptResult(null, AbortReason.USER_CANCELLED)
        );

        synchronized (promptLifecycleLock) {
            preCreationAbortReason = null;
            awaitingDialogCreation = true;
        }

        Runnable showTask = () -> {
            AntiKeyloggerKeypadDialog dialog;
            synchronized (promptLifecycleLock) {
                awaitingDialogCreation = false;
                if (preCreationAbortReason != null) {
                    resultHolder.set(new PinPromptResult(null, preCreationAbortReason));
                    preCreationAbortReason = null;
                    return;
                }
                dialog = new AntiKeyloggerKeypadDialog(null, title, operationHtmlDetails, timeoutSeconds);
                activeDialogRef.set(dialog);
            }
            try {
                resultHolder.set(dialog.promptPinResult());
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
            logger.error("Interrupted while waiting for PIN modal input: {}", e.getMessage(), e);
            abortActivePrompt(AbortReason.USER_CANCELLED);
        } finally {
            synchronized (promptLifecycleLock) {
                awaitingDialogCreation = false;
                preCreationAbortReason = null;
            }
        }

        return resultHolder.get();
    }

    @Override
    public void abortActivePromptForCardRemoval() {
        abortActivePrompt(AbortReason.CARD_REMOVED);
    }

    @Override
    public void abortActivePrompt(AbortReason reason) {
        AbortReason effectiveReason = reason != null ? reason : AbortReason.USER_CANCELLED;
        AntiKeyloggerKeypadDialog active;
        synchronized (promptLifecycleLock) {
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
