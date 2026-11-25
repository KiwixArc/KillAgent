package pe.ong.chasca.killagent.server.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Map;

/**
 * Outbound WebSocket success response ({@code type = "SIGN_AUTH_CHALLENGE_RESPONSE"}) carrying
 * the hardware-signed challenge proof and X.509 authentication certificate for Phase 2 backend
 * verification ({@code POST /api/v1/authentication/sign-in}).
 *
 * @param type      constant protocol discriminator, always {@code "SIGN_AUTH_CHALLENGE_RESPONSE"}
 * @param requestId correlation identifier echoed from {@link SignAuthChallengeRequest}
 * @param status    execution status string, {@code "SUCCESS"} for completed signatures
 * @param payload   cryptographic proof envelope containing signature, certificate PEM, session ID, and metadata
 */
public record SignAuthChallengeResponse(
        @JsonProperty("type") String type,
        @JsonProperty("requestId") String requestId,
        @JsonProperty("status") String status,
        @JsonProperty("payload") Payload payload
) {
    /**
     * Cryptographic proof payload returned to the Ch'aska frontend after DNIe challenge signing.
     *
     * @param nonce                trimmed challenge nonce that was signed
     * @param signedNonce          Base64-encoded {@code SHA256withRSA} signature produced by the DNIe chip
     * @param clientCertificatePem PEM-encoded X.509 Authentication certificate from the DNIe token
     * @param wsConnectionId       ephemeral WebSocket session identifier assigned in {@code CONNECTION_ESTABLISHED}
     * @param metadata             extracted citizen and hardware metadata ({@code dni}, {@code fullName},
     *                             {@code certificateSerialNumber}, {@code validTo}, {@code readerName},
     *                             {@code cardType}, {@code cardAtr})
     */
    public record Payload(
            @JsonProperty("nonce") String nonce,
            @JsonProperty("signedNonce") String signedNonce,
            @JsonProperty("clientCertificatePem") String clientCertificatePem,
            @JsonProperty("wsConnectionId") String wsConnectionId,
            @JsonProperty("metadata") Map<String, String> metadata
    ) {}

    /**
     * Builds a standardized {@code SUCCESS} response for {@code SIGN_AUTH_CHALLENGE}.
     *
     * @param requestId   correlated request identifier
     * @param nonce       trimmed challenge nonce
     * @param signedNonce Base64-encoded RSA signature
     * @param pem         PEM-encoded X.509 Authentication certificate
     * @param wsConnId    active WebSocket connection identifier
     * @param metadata    certificate and reader metadata map
     * @return populated {@link SignAuthChallengeResponse} ready for JSON serialization
     */
    public static SignAuthChallengeResponse success(String requestId, String nonce, String signedNonce, String pem, String wsConnId, Map<String, String> metadata) {
        return new SignAuthChallengeResponse(
                "SIGN_AUTH_CHALLENGE_RESPONSE",
                requestId,
                "SUCCESS",
                new Payload(nonce, signedNonce, pem, wsConnId, metadata)
        );
    }
}

