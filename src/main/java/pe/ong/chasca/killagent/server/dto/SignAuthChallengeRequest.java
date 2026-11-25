package pe.ong.chasca.killagent.server.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Inbound WebSocket command ({@code type = "SIGN_AUTH_CHALLENGE"}) requesting hardware proof-of-possession
 * over a backend-issued single-use cryptographic challenge nonce using the DNIe Authentication certificate
 * ({@code KeyUsage.digitalSignature}, without {@code nonRepudiation}).
 * <p>
 * Note on PIN isolation: no PIN field exists in this DTO; the user's PIN is captured locally
 * by {@code AntiKeyloggerKeypadDialog} and never enters the browser or JSON channel.
 * Untrusted UI strings ({@code operationTitle}, {@code operationDescription}) are sanitized/HTML-escaped
 * by {@code KillAgentWebSocketServer} before rendering in Swing modals.
 *
 * @param type                 command discriminator, expected to be {@code "SIGN_AUTH_CHALLENGE"}
 * @param requestId            client-generated correlation identifier echoed in the response or error
 * @param nonce                single-use challenge issued by Ch'aska backend (hex or UTF-8 token)
 * @param operationTitle       optional plain-text title displayed in the PIN / wait modal header
 * @param operationDescription optional contextual description displayed in the modal body (HTML-escaped)
 * @param waitForCard          when {@code true}, opens {@code WaitForCardDialog} up to 30s if no card is inserted
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record SignAuthChallengeRequest(
        @JsonProperty("type") String type,
        @JsonProperty("requestId") String requestId,
        @JsonProperty("nonce") String nonce,
        @JsonProperty("operationTitle") String operationTitle,
        @JsonProperty("operationDescription") String operationDescription,
        @JsonProperty("waitForCard") Boolean waitForCard
) {
    /**
     * Backward-compatible constructor defaulting {@code waitForCard} to {@link Boolean#FALSE}.
     *
     * @param type                 command discriminator
     * @param requestId            client correlation identifier
     * @param nonce                authentication challenge nonce
     * @param operationTitle       optional modal title
     * @param operationDescription optional modal description
     */
    public SignAuthChallengeRequest(
            String type,
            String requestId,
            String nonce,
            String operationTitle,
            String operationDescription
    ) {
        this(type, requestId, nonce, operationTitle, operationDescription, Boolean.FALSE);
    }
}
