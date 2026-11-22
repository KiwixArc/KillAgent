package pe.ong.chasca.killagent.server.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public record SignAuthChallengeRequest(
        @JsonProperty("type") String type,
        @JsonProperty("requestId") String requestId,
        @JsonProperty("nonce") String nonce,
        @JsonProperty("operationTitle") String operationTitle,
        @JsonProperty("operationDescription") String operationDescription,
        @JsonProperty("waitForCard") Boolean waitForCard
) {
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
