package pe.ong.chasca.killagent.security;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Decoded JSON payload inside a backend-signed {@link pe.ong.chasca.killagent.server.dto.SignedIntentEnvelope}.
 *
 * @param intentId      unique single-use intent identifier for anti-replay protection
 * @param operationType expected WebSocket operation ({@code "SIGN_DOCUMENT_DIGEST"} or {@code "SIGN_AUTH_CHALLENGE"})
 * @param slotId        bound signature slot identifier (required for {@code SIGN_DOCUMENT_DIGEST})
 * @param documentHash  bound 64-char SHA-256 hex digest or authentication challenge nonce
 * @param documentTitle trusted document title displayed in the WYSIWYS PIN dialog
 * @param signerRole    trusted institutional signer role displayed in the WYSIWYS PIN dialog
 * @param expectedDni   optional expected citizen DNI bound by the backend
 * @param expiresAt     ISO-8601 UTC expiration timestamp (e.g. {@code 2026-11-25T23:30:00Z})
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record SigningIntentPayload(
        @JsonProperty("intentId") String intentId,
        @JsonProperty("operationType") String operationType,
        @JsonProperty("slotId") String slotId,
        @JsonProperty("documentHash") String documentHash,
        @JsonProperty("documentTitle") String documentTitle,
        @JsonProperty("signerRole") String signerRole,
        @JsonProperty("expectedDni") String expectedDni,
        @JsonProperty("expiresAt") String expiresAt
) {}
