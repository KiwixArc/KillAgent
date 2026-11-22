package pe.ong.chasca.killagent.server.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;
import java.time.format.DateTimeFormatter;

/**
 * Push notification sent when smart card is inserted.
 */
public record CardInsertedNotification(
        @JsonProperty("type") String type,
        @JsonProperty("timestamp") String timestamp,
        @JsonProperty("readerName") String readerName
) {
    public CardInsertedNotification(String readerName) {
        this("CARD_INSERTED", DateTimeFormatter.ISO_INSTANT.format(Instant.now()), readerName);
    }
}

