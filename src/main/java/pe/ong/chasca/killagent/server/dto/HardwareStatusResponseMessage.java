package pe.ong.chasca.killagent.server.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import pe.ong.chasca.killagent.hardware.HardwareStatus;

/**
 * Outbound WebSocket response sent in reply to {@code GET_HARDWARE_STATUS} or {@code PING}
 * client commands, reporting the real-time PC/SC reader and DNIe smart-card state.
 *
 * @param type           constant protocol discriminator, always {@code "HARDWARE_STATUS_RESPONSE"}
 * @param requestId      correlation identifier echoed from the client status query
 * @param hardwareStatus immutable snapshot of the active reader, card presence, card generation
 *                       ({@link pe.ong.chasca.killagent.hardware.CardType}), and mock indicator
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record HardwareStatusResponseMessage(
        @JsonProperty("type") String type,
        @JsonProperty("requestId") String requestId,
        @JsonProperty("hardwareStatus") HardwareStatus hardwareStatus
) {
    /**
     * Creates a {@code HARDWARE_STATUS_RESPONSE} envelope for the given request ID and hardware snapshot.
     *
     * @param requestId      correlated client request identifier
     * @param hardwareStatus current {@link HardwareStatus} reported by {@code CardReaderManager}
     */
    public HardwareStatusResponseMessage(String requestId, HardwareStatus hardwareStatus) {
        this("HARDWARE_STATUS_RESPONSE", requestId, hardwareStatus);
    }
}

