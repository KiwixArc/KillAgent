package pe.ong.chasca.killagent.hardware;

import java.util.List;

/**
 * Abstraction for local PC/SC smart card hardware discovery and change notification.
 * Decouples {@link CardReaderManager} from native WinSCard JNA bindings and {@code javax.smartcardio}.
 */
public interface HardwareProbe extends AutoCloseable {

    /**
     * Immutable point-in-time state of a single smart card reader.
     */
    record ReaderSnapshot(String name, boolean cardPresent, byte[] atrBytes) {
        public ReaderSnapshot {
            atrBytes = atrBytes != null ? atrBytes.clone() : new byte[0];
        }

        @Override
        public byte[] atrBytes() {
            return atrBytes.clone();
        }
    }

    /**
     * Immutable point-in-time snapshot of all currently attached readers.
     */
    record Snapshot(List<ReaderSnapshot> readers) {
        public Snapshot {
            readers = readers != null ? List.copyOf(readers) : List.of();
        }

        public static Snapshot empty() {
            return new Snapshot(List.of());
        }
    }

    /**
     * Probes currently attached readers and their card presence/ATR without stale caching.
     */
    Snapshot probe();

    /**
     * Waits up to {@code timeoutMs} milliseconds for a reader hot-plug or card state change.
     */
    void waitForChange(int timeoutMs) throws InterruptedException;

    /**
     * Optionally cancels any blocking wait (e.g., during shutdown or mode switching).
     */
    default void cancelPendingWait() {
    }

    @Override
    default void close() {
    }
}
