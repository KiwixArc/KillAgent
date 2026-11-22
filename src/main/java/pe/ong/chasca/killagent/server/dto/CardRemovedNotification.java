package pe.ong.chasca.killagent.server.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;
import java.time.format.DateTimeFormatter;

/**
 * Push notification sent when smart card is physically removed (Kill-Switch trigger).
 */
public record CardRemovedNotification(
        @JsonProperty("type") String type,
        @JsonProperty("timestamp") String timestamp
) {
    public CardRemovedNotification() {
        this("CARD_REMOVED", DateTimeFormatter.ISO_INSTANT.format(Instant.now()));
    }
}

