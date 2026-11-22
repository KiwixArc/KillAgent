package pe.ong.chasca.killagent.hardware;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.smartcardio.Card;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.TerminalFactory;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Portable {@code javax.smartcardio} fallback {@link HardwareProbe} used on non-Windows platforms
 * or if native {@code Winscard.dll} cannot be loaded.
 * <p>
 * Unwraps the full {@link Throwable#getCause()} chain when diagnosing PC/SC context faults so
 * nested {@code PCSCException} messages ({@code SCARD_E_NO_READERS_AVAILABLE},
 * {@code SCARD_E_SERVICE_STOPPED}, etc.) are accurately detected and handled.
 */
public final class JavaSmartCardIoProbe implements HardwareProbe {

    private static final Logger logger = LoggerFactory.getLogger(JavaSmartCardIoProbe.class);

    public enum PcscFaultType {
        NONE,
        NO_READERS,
        SERVICE_OR_HANDLE_INVALID,
        READER_UNAVAILABLE
    }

    private volatile TerminalFactory terminalFactory;
    private final Map<String, byte[]> cachedAtrByReader = new ConcurrentHashMap<>();

    @Override
    public Snapshot probe() {
        TerminalFactory factory = ensureTerminalFactory();
        if (factory == null) {
            cachedAtrByReader.clear();
            return Snapshot.empty();
        }

        try {
            return probeTerminalsWithContext(factory.terminals());
        } catch (CardException ce) {
            handlePcscContextFault(ce);
            return Snapshot.empty();
        } catch (Exception e) {
            logger.debug("Unexpected javax.smartcardio probe failure: {}", e.getMessage());
            cachedAtrByReader.clear();
            return Snapshot.empty();
        }
    }

    private Snapshot probeTerminalsWithContext(CardTerminals terminals) throws CardException {
        List<CardTerminal> terminalList = terminals.list();
        if (terminalList.isEmpty()) {
            cachedAtrByReader.clear();
            return Snapshot.empty();
        }

        List<ReaderSnapshot> snapshots = new ArrayList<>(terminalList.size());
        Set<String> seenReaders = Collections.newSetFromMap(new ConcurrentHashMap<>());

        for (CardTerminal candidate : terminalList) {
            String name = candidate.getName();
            seenReaders.add(name);
            boolean cardPresent = false;
            try {
                cardPresent = candidate.isCardPresent();
            } catch (CardException ce) {
                PcscFaultType fault = classifyPcscFault(ce);
                if (fault != PcscFaultType.NONE) {
                    throw ce;
                }
            }

            byte[] atrBytes = new byte[0];
            if (cardPresent) {
                atrBytes = cachedAtrByReader.computeIfAbsent(name, ignored -> readAtrSafely(candidate));
            } else {
                cachedAtrByReader.remove(name);
            }
            snapshots.add(new ReaderSnapshot(name, cardPresent, atrBytes));
        }

        cachedAtrByReader.keySet().retainAll(seenReaders);
        return new Snapshot(snapshots);
    }

    @Override
    public void waitForChange(int timeoutMs) throws InterruptedException {
        int effectiveTimeout = Math.max(100, Math.min(timeoutMs, 1200));
        TerminalFactory factory = ensureTerminalFactory();
        if (factory == null) {
            Thread.sleep(Math.min(effectiveTimeout, 1000));
            return;
        }

        try {
            factory.terminals().waitForChange(effectiveTimeout);
        } catch (CardException ce) {
            handlePcscContextFault(ce);
            Thread.sleep(Math.min(effectiveTimeout, 1000));
        }
    }

    private TerminalFactory ensureTerminalFactory() {
        TerminalFactory current = this.terminalFactory;
        if (current != null) {
            return current;
        }
        try {
            TerminalFactory factory = TerminalFactory.getDefault();
            if ("None".equalsIgnoreCase(factory.getType())) {
                this.terminalFactory = null;
                logger.debug("PC/SC TerminalFactory returned 'None' provider.");
            } else {
                this.terminalFactory = factory;
            }
        } catch (Exception e) {
            this.terminalFactory = null;
            logger.warn("PC/SC subsystem unavailable: {}", e.getMessage());
        }
        return this.terminalFactory;
    }

    private void handlePcscContextFault(CardException ce) {
        PcscFaultType fault = classifyPcscFault(ce);
        switch (fault) {
            case NO_READERS, READER_UNAVAILABLE -> cachedAtrByReader.clear();
            case SERVICE_OR_HANDLE_INVALID -> {
                logger.warn("Windows Smart Card service handle invalidated ({}). Refreshing PC/SC context...",
                        ce.getMessage());
                cachedAtrByReader.clear();
                terminalFactory = null;
            }
            case NONE -> logger.debug("PC/SC CardException during probe/wait: {}", ce.getMessage());
        }
    }

    /**
     * Unwraps the entire {@link Throwable#getCause()} chain to classify PC/SC context errors
     * wrapped inside {@link CardException} (such as {@code "list() failed"}).
     */
    public static PcscFaultType classifyPcscFault(Throwable error) {
        Throwable current = error;
        Set<Throwable> visited = Collections.newSetFromMap(new IdentityHashMap<>());
        while (current != null && visited.add(current)) {
            String msg = current.getMessage();
            if (msg != null) {
                String upper = msg.toUpperCase(Locale.ROOT);
                if (upper.contains("SCARD_E_NO_READERS_AVAILABLE") || upper.contains("NO_READERS")) {
                    return PcscFaultType.NO_READERS;
                }
                if (upper.contains("SCARD_E_NO_SERVICE")
                        || upper.contains("SCARD_E_SERVICE_STOPPED")
                        || upper.contains("SCARD_E_INVALID_HANDLE")) {
                    return PcscFaultType.SERVICE_OR_HANDLE_INVALID;
                }
                if (upper.contains("SCARD_E_READER_UNAVAILABLE")
                        || upper.contains("SCARD_E_UNKNOWN_READER")) {
                    return PcscFaultType.READER_UNAVAILABLE;
                }
            }
            current = current.getCause();
        }
        return PcscFaultType.NONE;
    }

    private static byte[] readAtrSafely(CardTerminal terminal) {
        try {
            Card card = terminal.connect("*");
            try {
                return card.getATR().getBytes();
            } finally {
                card.disconnect(false);
            }
        } catch (Exception e) {
            logger.warn("Unable to read card ATR ({}); defaulting classification to DNIE_3_0.", e.getMessage());
            return new byte[0];
        }
    }

    @Override
    public void close() {
        cachedAtrByReader.clear();
        terminalFactory = null;
    }
}
