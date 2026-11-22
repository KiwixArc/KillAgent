package pe.ong.chasca.killagent.hardware;

/**
 * Callback listener for hardware state transitions (hot-plugging and card insertion/removal).
 */
public interface HardwareListener {
    void onCardInserted(String readerName, CardType cardType);
    void onCardRemoved(String readerName);
    void onReaderStatusChanged(boolean readerPresent, String readerName);
}

