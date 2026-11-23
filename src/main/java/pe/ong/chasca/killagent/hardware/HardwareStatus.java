package pe.ong.chasca.killagent.hardware;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Snapshot of local smart card hardware status.
 */
public record HardwareStatus(
        @JsonProperty("readerPresent") boolean readerPresent,
        @JsonProperty("cardPresent") boolean cardPresent,
        @JsonProperty("readerName") String readerName,
        @JsonProperty("cardType") CardType cardType,
        @JsonProperty("isMock") boolean isMock
) {
    public HardwareStatus(boolean readerPresent, boolean cardPresent, String readerName, CardType cardType) {
        this(readerPresent, cardPresent, readerName, cardType, false);
    }

    public static HardwareStatus noHardware() {
        return new HardwareStatus(false, false, null, CardType.NONE, false);
    }
}
