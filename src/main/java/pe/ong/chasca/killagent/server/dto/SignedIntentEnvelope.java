package pe.ong.chasca.killagent.server.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Ed25519-signed authorization envelope issued by the Ch'aska backend to bind
 * WebSocket signing parameters ({@code documentHash}, {@code slotId}, WYSIWYS metadata)
 * and prevent parameter tampering or replay attacks.
 *
 * @param payloadBase64Url   Base64URL-encoded UTF-8 JSON representation of {@code SigningIntentPayload}
 * @param signatureBase64Url Base64URL-encoded Ed25519 signature over the UTF-8 bytes of {@code payloadBase64Url}
 * @param algorithm          signature algorithm identifier, expected to be {@code "Ed25519"}
 * @param keyId              optional backend signing key identifier
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record SignedIntentEnvelope(
        @JsonProperty("payloadBase64Url") String payloadBase64Url,
        @JsonProperty("signatureBase64Url") String signatureBase64Url,
        @JsonProperty("algorithm") String algorithm,
        @JsonProperty("keyId") String keyId
) {}
