package pe.ong.chasca.killagent.server.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ErrorMessage(
        @JsonProperty("type") String type,
        @JsonProperty("requestId") String requestId,
        @JsonProperty("errorCode") ErrorCode errorCode,
        @JsonProperty("message") String message,
        @JsonProperty("attemptsRemaining") Integer attemptsRemaining
) {
    public ErrorMessage(String requestId, ErrorCode errorCode, String message, Integer attemptsRemaining) {
        this("ERROR", requestId, errorCode, message, attemptsRemaining);
    }

    public ErrorMessage(String requestId, ErrorCode errorCode, String message) {
        this("ERROR", requestId, errorCode, message, null);
    }
}

