package pe.ong.chasca.killagent.server.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import pe.ong.chasca.killagent.hardware.HardwareStatus;

/**
 * Sent to frontend immediately upon successful WebSocket handshake and origin validation.
 */
public record ConnectionEstablishedMessage(
        @JsonProperty("type") String type,
        @JsonProperty("wsConnectionId") String wsConnectionId,
        @JsonProperty("version") String version,
        @JsonProperty("hardwareStatus") HardwareStatus hardwareStatus
) {
    public ConnectionEstablishedMessage(String wsConnectionId, String version, HardwareStatus hardwareStatus) {
        this("CONNECTION_ESTABLISHED", wsConnectionId, version, hardwareStatus);
    }
}

