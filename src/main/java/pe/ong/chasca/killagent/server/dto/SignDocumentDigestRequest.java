package pe.ong.chasca.killagent.server.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public record SignDocumentDigestRequest(
        @JsonProperty("type") String type,
        @JsonProperty("requestId") String requestId,
        @JsonProperty("slotId") String slotId,
        @JsonProperty("documentHash") String documentHash,
        @JsonProperty("documentTitle") String documentTitle,
        @JsonProperty("signerRole") String signerRole
) {}
