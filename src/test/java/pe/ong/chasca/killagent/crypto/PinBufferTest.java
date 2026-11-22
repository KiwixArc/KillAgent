package pe.ong.chasca.killagent.crypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PinBufferTest {

    @Test
    void testPinBufferSanitizationOnClose() {
        char[] original = new char[]{'1', '2', '3', '4', '5', '6'};
        PinBuffer buffer = new PinBuffer(original);

        assertArrayEquals(new char[]{'1', '2', '3', '4', '5', '6'}, buffer.getPin());

        // Close buffer
        buffer.close();

        // After close, attempting to read should throw or be zeroed
        assertThrows(IllegalStateException.class, buffer::getPin);
    }
}

