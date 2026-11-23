package pe.ong.chasca.killagent.testsupport;

import pe.ong.chasca.killagent.hardware.HardwareProbe;

import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Mutable test-only PC/SC HardwareProbe allowing unit and integration tests
 * to script physical card insertion, removal, and reader disconnect transitions
 * without embedding any mock logic in production artifacts.
 */
public final class MutableTestHardwareProbe implements HardwareProbe {

    public static final byte[] DNIE_3_ATR = HexFormat.of().parseHex("3B7F96000080318065B085040120120FFF829000");
    public static final String DEFAULT_READER_NAME = "Identiv uTrust 2700 R Smart Card Reader 0";

    private final AtomicReference<Snapshot> snapshotRef;

    public MutableTestHardwareProbe(boolean initiallyPresent) {
        this.snapshotRef = new AtomicReference<>(
                initiallyPresent ? cardInsertedSnapshot(DEFAULT_READER_NAME) : Snapshot.empty()
        );
    }

    public static Snapshot cardInsertedSnapshot(String readerName) {
        return new Snapshot(List.of(new ReaderSnapshot(readerName, true, DNIE_3_ATR)));
    }

    public static Snapshot readerEmptySnapshot(String readerName) {
        return new Snapshot(List.of(new ReaderSnapshot(readerName, false, new byte[0])));
    }

    public void insertCard() {
        insertCard(DEFAULT_READER_NAME);
    }

    public void insertCard(String readerName) {
        snapshotRef.set(cardInsertedSnapshot(readerName));
    }

    public void removeCard() {
        removeCard(DEFAULT_READER_NAME);
    }

    public void removeCard(String readerName) {
        snapshotRef.set(readerEmptySnapshot(readerName));
    }

    public void disconnectReader() {
        snapshotRef.set(Snapshot.empty());
    }

    public void setSnapshot(Snapshot snapshot) {
        snapshotRef.set(snapshot != null ? snapshot : Snapshot.empty());
    }

    @Override
    public Snapshot probe() {
        return snapshotRef.get();
    }

    @Override
    public void waitForChange(int timeoutMs) {
    }
}
