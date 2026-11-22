package pe.ong.chasca.killagent.crypto;

import java.util.Arrays;

/**
 * Memory-safe container for sensitive PIN characters with deterministic zeroization on close.
 * Never converts or exposes the PIN as a {@link String}.
 */
public final class PinBuffer implements AutoCloseable {

    private final char[] pin;
    private volatile boolean closed = false;

    public PinBuffer(char[] pin) {
        this.pin = pin != null ? Arrays.copyOf(pin, pin.length) : new char[0];
    }

    private PinBuffer(char[] pin, boolean adoptDirectly) {
        this.pin = pin != null ? (adoptDirectly ? pin : Arrays.copyOf(pin, pin.length)) : new char[0];
    }

    /**
     * Takes direct ownership of the provided char[] buffer without creating a second copy in heap memory.
     * Closing this PinBuffer will overwrite the adopted array in-place with '\0'.
     */
    public static PinBuffer adopt(char[] rawPinBuffer) {
        return new PinBuffer(rawPinBuffer, true);
    }

    public char[] getPin() {
        if (closed) {
            throw new IllegalStateException("PinBuffer has already been sanitized and closed.");
        }
        return pin;
    }

    public int length() {
        if (closed) {
            return 0;
        }
        return pin.length;
    }

    public boolean isClosed() {
        return closed;
    }

    @Override
    public void close() {
        if (!closed) {
            Arrays.fill(pin, '\0');
            closed = true;
        }
    }
}
