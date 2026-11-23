package pe.ong.chasca.killagent.hardware;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pe.ong.chasca.killagent.config.AgentConfig;
import pe.ong.chasca.killagent.hardware.winscard.WinSCardReaderProbe;

import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Manages PC/SC smart card terminals (via native Windows WinSCard JNA on Windows or
 * {@code javax.smartcardio} fallback on other platforms), delivering sub-10ms event detection
 * for card insertion, card removal (Kill-Switch), and USB reader hot-plugging.
 */
public class CardReaderManager implements Runnable {

    private static final Logger logger = LoggerFactory.getLogger(CardReaderManager.class);
    private static final int MONITOR_WAIT_TIMEOUT_MS = 350;

    private final AgentConfig config;
    private final HardwareProbe hardwareProbe;
    private final List<HardwareListener> listeners = new CopyOnWriteArrayList<>();
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final Object stateLock = new Object();
    private final Object probeLock = new Object();

    private volatile Thread monitorThread;
    private volatile String activeReaderName;
    private volatile boolean cardCurrentlyPresent;
    private volatile CardType currentCardType = CardType.NONE;
    private volatile String lastDetectedAtrHex = "";
    private volatile String activeCardholderDni = null;
    private volatile String activeCardholderName = null;

    public CardReaderManager(AgentConfig config) {
        this(config, createDefaultProbe());
    }

    public CardReaderManager(AgentConfig config, HardwareProbe hardwareProbe) {
        this.config = Objects.requireNonNull(config, "config must not be null");
        this.hardwareProbe = Objects.requireNonNull(hardwareProbe, "hardwareProbe must not be null");
    }

    private static HardwareProbe createDefaultProbe() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (os.contains("win")) {
            try {
                WinSCardReaderProbe nativeProbe = new WinSCardReaderProbe();
                logger.info("Using native Windows WinSCard JNA hardware monitor.");
                return nativeProbe;
            } catch (Throwable t) {
                logger.warn("Native WinSCard probe unavailable ({}); falling back to javax.smartcardio.", t.getMessage());
            }
        }
        return new JavaSmartCardIoProbe();
    }

    public void addListener(HardwareListener listener) {
        if (listener != null) {
            listeners.add(listener);
        }
    }

    public void removeListener(HardwareListener listener) {
        listeners.remove(listener);
    }

    public HardwareStatus getStatus() {
        synchronized (stateLock) {
            String name = activeReaderName;
            boolean readerPresent = name != null;
            return new HardwareStatus(readerPresent, cardCurrentlyPresent, name, currentCardType, false);
        }
    }

    public String getLastDetectedAtrHex() {
        return lastDetectedAtrHex;
    }

    public String getActiveCardholderDni() {
        return activeCardholderDni;
    }

    public String getActiveCardholderName() {
        return activeCardholderName;
    }

    /**
     * Records public cardholder identity metadata read from the X.509 certificate
     * so the System Tray pill and Diagnostics Panel can show masked DNI status.
     */
    public void updateDetectedCardholderIdentity(String dni, String fullName) {
        synchronized (stateLock) {
            if (cardCurrentlyPresent) {
                this.activeCardholderDni = dni;
                this.activeCardholderName = fullName;
            }
        }
    }

    public void start() {
        if (running.compareAndSet(false, true)) {
            probeOnce(false);
            Thread thread = new Thread(this, "killagent-pcsc-monitor");
            thread.setDaemon(true);
            this.monitorThread = thread;
            thread.start();
            logger.info("PC/SC CardReaderManager monitor thread started (env={}).", config.environment());
        }
    }

    public void stop() {
        running.set(false);
        hardwareProbe.cancelPendingWait();
        Thread thread = this.monitorThread;
        if (thread != null) {
            thread.interrupt();
        }
        if (thread == null) {
            try {
                hardwareProbe.close();
            } catch (Exception e) {
                logger.debug("Error closing hardware probe: {}", e.getMessage());
            }
        }
    }

    @Override
    public void run() {
        this.monitorThread = Thread.currentThread();
        try {
            while (running.get()) {
                try {
                    probeOnce(true);
                    if (!running.get()) {
                        break;
                    }
                    hardwareProbe.waitForChange(MONITOR_WAIT_TIMEOUT_MS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (Exception e) {
                    logger.debug("PC/SC monitor cycle exception: {}", e.getMessage());
                    try {
                        Thread.sleep(500);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            }
        } finally {
            this.monitorThread = null;
            try {
                hardwareProbe.close();
            } catch (Exception e) {
                logger.debug("Error closing hardware probe: {}", e.getMessage());
            }
        }
    }

    public void probeOnce(boolean emitEvents) {
        HardwareProbe.Snapshot snapshot;
        synchronized (probeLock) {
            try {
                snapshot = hardwareProbe.probe();
            } catch (Exception e) {
                logger.warn("Hardware probe failed ({}); clearing active reader state.", e.getMessage());
                snapshot = HardwareProbe.Snapshot.empty();
            }
        }
        applySnapshot(snapshot, emitEvents);
    }

    private void applySnapshot(HardwareProbe.Snapshot snapshot, boolean emitEvents) {
        List<Runnable> pendingEvents = new ArrayList<>();

        synchronized (stateLock) {
            List<HardwareProbe.ReaderSnapshot> readers = snapshot != null ? snapshot.readers() : List.of();
            if (readers.isEmpty()) {
                collectNoReadersEventsLocked(emitEvents, pendingEvents);
            } else {
                HardwareProbe.ReaderSnapshot selected = selectActiveReader(readers);
                String selectedName = selected.name();
                String previousName = this.activeReaderName;

                if (previousName != null && !previousName.equals(selectedName)) {
                    if (cardCurrentlyPresent) {
                        cardCurrentlyPresent = false;
                        currentCardType = CardType.NONE;
                        clearCardIdentity();
                        logger.info("Smart card REMOVED from [{}] due to reader switch — Kill-Switch triggered!", previousName);
                        if (emitEvents) {
                            pendingEvents.add(() -> notifyCardRemoved(previousName));
                        }
                    }
                    this.activeReaderName = selectedName;
                    logger.info("Active PC/SC smart card reader detected: {}", selectedName);
                    if (emitEvents) {
                        pendingEvents.add(() -> notifyReaderStatus(true, selectedName));
                    }
                } else if (previousName == null) {
                    this.activeReaderName = selectedName;
                    logger.info("Active PC/SC smart card reader detected: {}", selectedName);
                    if (emitEvents) {
                        pendingEvents.add(() -> notifyReaderStatus(true, selectedName));
                    }
                }

                boolean isPresentNow = selected.cardPresent();
                if (isPresentNow && !cardCurrentlyPresent) {
                    cardCurrentlyPresent = true;
                    currentCardType = classifyAtrHex(selected.atrBytes());
                    CardType detectedType = currentCardType;
                    logger.info("Smart card INSERTED in [{}], classified as: {} (ATR={})",
                            selectedName, detectedType, lastDetectedAtrHex);
                    if (emitEvents) {
                        pendingEvents.add(() -> notifyCardInserted(selectedName, detectedType));
                    }
                } else if (!isPresentNow && cardCurrentlyPresent) {
                    cardCurrentlyPresent = false;
                    currentCardType = CardType.NONE;
                    clearCardIdentity();
                    logger.info("Smart card REMOVED from [{}] — Kill-Switch triggered!", selectedName);
                    if (emitEvents) {
                        pendingEvents.add(() -> notifyCardRemoved(selectedName));
                    }
                }
            }
        }

        dispatchEvents(pendingEvents);
    }

    private static HardwareProbe.ReaderSnapshot selectActiveReader(List<HardwareProbe.ReaderSnapshot> readers) {
        for (HardwareProbe.ReaderSnapshot candidate : readers) {
            if (candidate.cardPresent()) {
                return candidate;
            }
        }
        return readers.getFirst();
    }

    private void collectNoReadersEventsLocked(boolean emitEvents, List<Runnable> pendingEvents) {
        boolean hadReader = activeReaderName != null;
        boolean hadCard = cardCurrentlyPresent;
        if (!hadReader && !hadCard) {
            return;
        }

        String previousName = hadReader ? activeReaderName : "DISCONNECTED_READER";
        activeReaderName = null;
        cardCurrentlyPresent = false;
        currentCardType = CardType.NONE;
        clearCardIdentity();

        logger.info("No PC/SC smart card readers detected (previousReader={}).", previousName);
        if (hadCard && emitEvents) {
            pendingEvents.add(() -> notifyCardRemoved(previousName));
        }
        if (emitEvents) {
            pendingEvents.add(() -> notifyReaderStatus(false, null));
        }
    }

    CardType classifyAtrHex(byte[] atrBytes) {
        if (atrBytes == null || atrBytes.length == 0) {
            logger.warn("Unable to read card ATR (empty bytes); defaulting classification to DNIE_3_0.");
            this.lastDetectedAtrHex = "UNAVAILABLE";
            return CardType.DNIE_3_0;
        }

        String atrHex = HexFormat.of().withUpperCase().formatHex(atrBytes);
        this.lastDetectedAtrHex = atrHex;

        // Known RENIEC DNIe ATR signatures:
        // IDEMIA Cosmo ID-One (DNIe 3.0) / Oberthur / Morpho patterns vs Bit4id (DNIe 2.0)
        if (atrHex.startsWith("3B7F96")
                || atrHex.startsWith("3BFF96")
                || atrHex.startsWith("3BDF96")
                || atrHex.startsWith("3B8F80")
                || atrHex.contains("4944454D4941") // "IDEMIA" ASCII
                || atrHex.contains("4A434F50")) {  // JCOP v3+
            return CardType.DNIE_3_0;
        }
        if (atrHex.startsWith("3B7E94") || atrHex.startsWith("3BF813") || atrHex.startsWith("3B9F95")) {
            return CardType.DNIE_2_0;
        }
        // Default modern Peruvian DNIe cards issued since 2020 are DNIe 3.0 (IDEMIA)
        return CardType.DNIE_3_0;
    }

    private void clearCardIdentity() {
        this.lastDetectedAtrHex = "";
        this.activeCardholderDni = null;
        this.activeCardholderName = null;
    }

    private static void dispatchEvents(List<Runnable> events) {
        for (Runnable event : events) {
            event.run();
        }
    }

    private void notifyCardInserted(String readerName, CardType cardType) {
        for (HardwareListener l : listeners) {
            try {
                l.onCardInserted(readerName, cardType);
            } catch (Exception e) {
                logger.error("HardwareListener error in onCardInserted: {}", e.getMessage(), e);
            }
        }
    }

    private void notifyCardRemoved(String readerName) {
        for (HardwareListener l : listeners) {
            try {
                l.onCardRemoved(readerName);
            } catch (Exception e) {
                logger.error("HardwareListener error in onCardRemoved: {}", e.getMessage(), e);
            }
        }
    }

    private void notifyReaderStatus(boolean present, String readerName) {
        for (HardwareListener l : listeners) {
            try {
                l.onReaderStatusChanged(present, readerName);
            } catch (Exception e) {
                logger.error("HardwareListener error in onReaderStatusChanged: {}", e.getMessage(), e);
            }
        }
    }
}
