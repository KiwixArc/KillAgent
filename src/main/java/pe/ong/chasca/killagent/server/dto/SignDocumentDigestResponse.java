package pe.ong.chasca.killagent.server.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record SignDocumentDigestResponse(
        @JsonProperty("type") String type,
        @JsonProperty("requestId") String requestId,
        @JsonProperty("status") String status,
        @JsonProperty("payload") Payload payload
) {
    public record Payload(
            @JsonProperty("slotId") String slotId,
            @JsonProperty("certificateDni") String certificateDni,
            @JsonProperty("documentHash") String documentHash,
            @JsonProperty("signatureValue") String signatureValue,
            @JsonProperty("signerSubjectDn") String signerSubjectDn,
            @JsonProperty("certificateSerialNumber") String certificateSerialNumber,
            @JsonProperty("clientCertificatePem") String clientCertificatePem
    ) {}

    public static SignDocumentDigestResponse success(
            String requestId,
            String slotId,
            String certificateDni,
            String documentHash,
            String signatureValue,
            String signerSubjectDn,
            String certificateSerialNumber,
            String clientCertificatePem
    ) {
        return new SignDocumentDigestResponse(
                "SIGN_DOCUMENT_DIGEST_RESPONSE",
                requestId,
                "SUCCESS",
                new Payload(slotId, certificateDni, documentHash, signatureValue, signerSubjectDn, certificateSerialNumber, clientCertificatePem)
        );
    }
}

