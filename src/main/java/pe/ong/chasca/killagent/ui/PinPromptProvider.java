package pe.ong.chasca.killagent.ui;

/**
 * Abstraction for secure local PIN acquisition, decoupling hardware/network orchestration
 * from the desktop windowing toolkit and enabling deterministic integration testing.
 */
public interface PinPromptProvider {

    enum AbortReason {
        NONE,
        USER_CANCELLED,
        CARD_REMOVED,
        TIMEOUT,
        CLIENT_DISCONNECTED
    }

    record PinPromptResult(char[] pin, AbortReason abortReason) {
        public boolean isConfirmed() {
            return abortReason == AbortReason.NONE && pin != null && pin.length > 0;
        }
    }

    /**
     * Prompts the local workstation user to enter their DNIe PIN via the anti-keylogger interface.
     */
    PinPromptResult requestPin(String title, String operationHtmlDetails);

    /**
     * Prompts the local workstation user to enter their DNIe PIN with a bounded timeout in seconds.
     */
    default PinPromptResult requestPin(String title, String operationHtmlDetails, int timeoutSeconds) {
        return requestPin(title, operationHtmlDetails);
    }

    /**
     * Immediately aborts and sanitizes any active PIN prompt when the physical smart card is removed.
     */
    void abortActivePromptForCardRemoval();

    /**
     * Immediately aborts and sanitizes any active PIN prompt for the specified reason.
     */
    default void abortActivePrompt(AbortReason reason) {
        if (reason == AbortReason.CARD_REMOVED) {
            abortActivePromptForCardRemoval();
        }
    }
}

