package pe.ong.chasca.killagent.server.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Map;

public record SignAuthChallengeResponse(
        @JsonProperty("type") String type,
        @JsonProperty("requestId") String requestId,
        @JsonProperty("status") String status,
        @JsonProperty("payload") Payload payload
) {
    public record Payload(
            @JsonProperty("nonce") String nonce,
            @JsonProperty("signedNonce") String signedNonce,
            @JsonProperty("clientCertificatePem") String clientCertificatePem,
            @JsonProperty("wsConnectionId") String wsConnectionId,
            @JsonProperty("metadata") Map<String, String> metadata
    ) {}

    public static SignAuthChallengeResponse success(String requestId, String nonce, String signedNonce, String pem, String wsConnId, Map<String, String> metadata) {
        return new SignAuthChallengeResponse(
                "SIGN_AUTH_CHALLENGE_RESPONSE",
                requestId,
                "SUCCESS",
                new Payload(nonce, signedNonce, pem, wsConnId, metadata)
        );
    }
}

