package pe.ong.chasca.killagent.server.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import pe.ong.chasca.killagent.hardware.HardwareStatus;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record HardwareStatusResponseMessage(
        @JsonProperty("type") String type,
        @JsonProperty("requestId") String requestId,
        @JsonProperty("hardwareStatus") HardwareStatus hardwareStatus
) {
    public HardwareStatusResponseMessage(String requestId, HardwareStatus hardwareStatus) {
        this("HARDWARE_STATUS_RESPONSE", requestId, hardwareStatus);
    }
}

