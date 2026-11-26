package pe.ong.chasca.killagent.server.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Outbound WebSocket response ({@code type = "SIGNING_CERTIFICATE_RESPONSE"}) returning
 * the cached or unauthenticated Non-Repudiation X.509 signing certificate when available
 * without prompting for the smartcard PIN.
 *
 * @param type                    constant protocol discriminator, always {@code "SIGNING_CERTIFICATE_RESPONSE"}
 * @param requestId               correlation identifier echoed from {@code GET_SIGNING_CERTIFICATE}
 * @param certificatePem          PEM-encoded X.509 Non-Repudiation certificate, or {@code null} if unavailable without PIN
 * @param certificateDni          8-digit Peruvian DNI extracted from certificate, or {@code null}
 * @param certificateSerialNumber uppercase hexadecimal certificate serial number, or {@code null}
 */
public record SigningCertificateResponseMessage(
        @JsonProperty("type") String type,
        @JsonProperty("requestId") String requestId,
        @JsonProperty("certificatePem") String certificatePem,
        @JsonProperty("certificateDni") String certificateDni,
        @JsonProperty("certificateSerialNumber") String certificateSerialNumber
) {
    public SigningCertificateResponseMessage(
            String requestId,
            String certificatePem,
            String certificateDni,
            String certificateSerialNumber
    ) {
        this("SIGNING_CERTIFICATE_RESPONSE", requestId, certificatePem, certificateDni, certificateSerialNumber);
    }
}
