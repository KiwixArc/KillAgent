package pe.ong.chasca.killagent.server.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;

/**
 * Push notification sent when a PC/SC smart card reader is connected or disconnected.
 */
public record ReaderStatusNotification(
        @JsonProperty("type") String type,
        @JsonProperty("readerPresent") boolean readerPresent,
        @JsonProperty("readerName") String readerName,
        @JsonProperty("timestamp") String timestamp
) {
    public ReaderStatusNotification {
        if (type == null || type.isBlank()) {
            type = "READER_STATUS_CHANGED";
        }
        if (timestamp == null || timestamp.isBlank()) {
            timestamp = Instant.now().toString();
        }
    }

    public ReaderStatusNotification(boolean readerPresent, String readerName) {
        this("READER_STATUS_CHANGED", readerPresent, readerName, Instant.now().toString());
    }
}
