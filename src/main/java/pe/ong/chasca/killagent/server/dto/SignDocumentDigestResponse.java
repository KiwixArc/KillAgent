package pe.ong.chasca.killagent.server.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Outbound WebSocket success response ({@code type = "SIGN_DOCUMENT_DIGEST_RESPONSE"}) returning
 * the PKCS#1 v1.5 RSA signature and Non-Repudiation X.509 certificate required by the Ch'aska
 * backend to assemble and embed a PAdES-LTV signature container.
 *
 * @param type      constant protocol discriminator, always {@code "SIGN_DOCUMENT_DIGEST_RESPONSE"}
 * @param requestId correlation identifier echoed from {@link SignDocumentDigestRequest}
 * @param status    execution status string, {@code "SUCCESS"} for completed signatures
 * @param payload   signed digest output and signer certificate metadata
 */
public record SignDocumentDigestResponse(
        @JsonProperty("type") String type,
        @JsonProperty("requestId") String requestId,
        @JsonProperty("status") String status,
        @JsonProperty("payload") Payload payload
) {
    /**
     * PAdES signature payload returned after Non-Repudiation hardware signing.
     *
     * @param slotId                  signature slot identifier echoed from the request
     * @param certificateDni          8-digit Peruvian DNI extracted from certificate {@code SERIALNUMBER}
     * @param documentHash            trimmed 64-char SHA-256 hex digest that was signed
     * @param signatureValue          Base64-encoded RSA signature over the RFC 8017 DigestInfo (or configured mode)
     * @param signerSubjectDn         canonical RENIEC Subject DN string ({@code CN=..., SERIALNUMBER=..., O=..., C=PE})
     * @param certificateSerialNumber uppercase hexadecimal X.509 certificate serial number
     * @param clientCertificatePem    PEM-encoded X.509 Non-Repudiation certificate
     */
    public record Payload(
            @JsonProperty("slotId") String slotId,
            @JsonProperty("certificateDni") String certificateDni,
            @JsonProperty("documentHash") String documentHash,
            @JsonProperty("signatureValue") String signatureValue,
            @JsonProperty("signerSubjectDn") String signerSubjectDn,
            @JsonProperty("certificateSerialNumber") String certificateSerialNumber,
            @JsonProperty("clientCertificatePem") String clientCertificatePem
    ) {}

    /**
     * Builds a standardized {@code SUCCESS} response for {@code SIGN_DOCUMENT_DIGEST}.
     *
     * @param requestId               correlated request identifier
     * @param slotId                  document signature slot identifier
     * @param certificateDni          8-digit DNI extracted from the signing certificate
     * @param documentHash            trimmed SHA-256 hex digest
     * @param signatureValue          Base64-encoded RSA signature
     * @param signerSubjectDn         canonical RENIEC Subject DN
     * @param certificateSerialNumber uppercase hex certificate serial number
     * @param clientCertificatePem    PEM-encoded X.509 certificate
     * @return populated {@link SignDocumentDigestResponse} ready for JSON serialization
     */
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

