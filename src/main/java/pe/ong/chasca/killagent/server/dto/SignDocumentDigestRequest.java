package pe.ong.chasca.killagent.server.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Inbound WebSocket command ({@code type = "SIGN_DOCUMENT_DIGEST"}) requesting a PAdES-LTV
 * digital signature over a precomputed 64-character hexadecimal SHA-256 document digest using
 * the DNIe Non-Repudiation / Content Commitment certificate (Peruvian Law N° 27269).
 * <p>
 * Untrusted descriptive fields ({@code documentTitle}, {@code signerRole}, {@code documentHash})
 * are HTML-escaped by {@code KillAgentWebSocketServer} before rendering in the PIN dialog.
 *
 * @param type          command discriminator, expected to be {@code "SIGN_DOCUMENT_DIGEST"}
 * @param requestId     client-generated correlation identifier echoed in the response or error
 * @param slotId        target signature slot identifier within the Ch'aska document version
 * @param documentHash  64-character hexadecimal SHA-256 digest of the PDF signed byte range / attributes
 * @param documentTitle human-readable document title shown in the PIN confirmation prompt
 * @param signerRole    institutional role label shown in the PIN confirmation prompt (defaults to {@code SIGNER})
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record SignDocumentDigestRequest(
        @JsonProperty("type") String type,
        @JsonProperty("requestId") String requestId,
        @JsonProperty("slotId") String slotId,
        @JsonProperty("documentHash") String documentHash,
        @JsonProperty("documentTitle") String documentTitle,
        @JsonProperty("signerRole") String signerRole
) {}
