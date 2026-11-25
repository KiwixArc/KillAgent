package pe.ong.chasca.killagent.crypto;

import java.util.Arrays;

/**
 * Memory-safe container for sensitive smart-card PIN characters with deterministic heap
 * zeroization on {@link #close()}.
 * <p>
 * <strong>Zero-String Memory Invariant:</strong> Never converts or exposes the PIN as an
 * immutable {@link java.lang.String} (which would linger on the JVM heap/String pool until GC).
 * All callers must wrap usage in {@code try-with-resources} so {@link Arrays#fill(char[], char)}
 * overwrites the backing {@code char[]} with {@code '\0'} immediately after PKCS#11 {@code C_Login},
 * including on failure paths.
 */
public final class PinBuffer implements AutoCloseable {

    private final char[] pin;
    private volatile boolean closed = false;

    /**
     * Creates a defensive copy of the supplied PIN character array.
     * Callers remain responsible for zeroizing their source {@code char[]} if retained.
     *
     * @param pin source PIN characters, or {@code null} for an empty buffer
     */
    public PinBuffer(char[] pin) {
        this.pin = pin != null ? Arrays.copyOf(pin, pin.length) : new char[0];
    }

    private PinBuffer(char[] pin, boolean adoptDirectly) {
        this.pin = pin != null ? (adoptDirectly ? pin : Arrays.copyOf(pin, pin.length)) : new char[0];
    }

    /**
     * Takes direct ownership of the provided {@code char[]} buffer without creating a second
     * copy in heap memory. Closing this {@code PinBuffer} overwrites the adopted array in-place
     * with {@code '\0'}, minimizing sensitive residue window in RAM.
     *
     * @param rawPinBuffer caller-owned {@code char[]} buffer containing the raw PIN
     * @return a {@code PinBuffer} owning {@code rawPinBuffer} directly
     */
    public static PinBuffer adopt(char[] rawPinBuffer) {
        return new PinBuffer(rawPinBuffer, true);
    }

    /**
     * Returns the backing PIN character array while the buffer remains open.
     *
     * @return mutable {@code char[]} passed directly to SunPKCS11 {@code KeyStore.load(null, pin)}
     * @throws IllegalStateException if {@link #close()} has already zeroized this buffer
     */
    public char[] getPin() {
        if (closed) {
            throw new IllegalStateException("PinBuffer has already been sanitized and closed.");
        }
        return pin;
    }

    /**
     * Returns the number of PIN characters currently held, or {@code 0} once closed.
     *
     * @return PIN length, or {@code 0} after sanitization
     */
    public int length() {
        if (closed) {
            return 0;
        }
        return pin.length;
    }

    /**
     * Indicates whether this buffer has already been zeroized via {@link #close()}.
     *
     * @return {@code true} if sanitized and closed
     */
    public boolean isClosed() {
        return closed;
    }

    /**
     * Deterministically overwrites every element of the backing {@code char[]} with {@code '\0'}
     * and marks the buffer closed to prevent subsequent reads. Idempotent.
     */
    @Override
    public void close() {
        if (!closed) {
            Arrays.fill(pin, '\0');
            closed = true;
        }
    }
}
