package pe.ong.chasca.killagent.ui;

import pe.ong.chasca.killagent.hardware.CardReaderManager;

/**
 * Abstraction for prompting the local workstation user to insert a DNIe smart card
 * before proceeding to PIN verification (used exclusively when requested by login flows).
 */
public interface CardWaitProvider {

    enum WaitOutcome {
        CARD_READY,
        USER_CANCELLED,
        TIMEOUT,
        CLIENT_DISCONNECTED
    }

    WaitOutcome waitForCard(
            CardReaderManager readerManager,
            String title,
            String operationHtmlDetails,
            int timeoutSeconds
    );

    void abortActiveWait(WaitOutcome reason);
}
