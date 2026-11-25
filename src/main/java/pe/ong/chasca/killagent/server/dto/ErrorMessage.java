package pe.ong.chasca.killagent.server.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Outbound WebSocket error envelope emitted by {@code KillAgentWebSocketServer} whenever a
 * request fails validation, hardware access, PIN verification, or cryptographic execution.
 * <p>
 * Serialized JSON omits {@code null} fields ({@link JsonInclude.Include#NON_NULL}), so
 * {@code attemptsRemaining} is only transmitted for {@link ErrorCode#PIN_INCORRECT} and
 * {@link ErrorCode#PIN_LOCKED} responses when a retry estimate or hardware count is available.
 *
 * @param type              constant protocol discriminator, always {@code "ERROR"}
 * @param requestId         correlation identifier echoed from the triggering client request, or
 *                          {@code null} when frame parsing failed before extracting an ID
 * @param errorCode         standardized error taxonomy value from {@link ErrorCode}
 * @param message           human-readable localized diagnostic description safe for UI display
 *                          (never exposes raw PIN data or internal stack traces)
 * @param attemptsRemaining optional remaining smart-card PIN retry count before chip lock
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ErrorMessage(
        @JsonProperty("type") String type,
        @JsonProperty("requestId") String requestId,
        @JsonProperty("errorCode") ErrorCode errorCode,
        @JsonProperty("message") String message,
        @JsonProperty("attemptsRemaining") Integer attemptsRemaining
) {
    /**
     * Constructs a protocol {@code ERROR} response including remaining PIN attempt metadata.
     *
     * @param requestId         correlated client request identifier (may be {@code null})
     * @param errorCode         standardized {@link ErrorCode}
     * @param message           user-facing error message
     * @param attemptsRemaining remaining PIN attempts, or {@code null} if not applicable
     */
    public ErrorMessage(String requestId, ErrorCode errorCode, String message, Integer attemptsRemaining) {
        this("ERROR", requestId, errorCode, message, attemptsRemaining);
    }

    /**
     * Constructs a protocol {@code ERROR} response without PIN attempt count metadata.
     *
     * @param requestId correlated client request identifier (may be {@code null})
     * @param errorCode standardized {@link ErrorCode}
     * @param message   user-facing error message
     */
    public ErrorMessage(String requestId, ErrorCode errorCode, String message) {
        this("ERROR", requestId, errorCode, message, null);
    }
}

