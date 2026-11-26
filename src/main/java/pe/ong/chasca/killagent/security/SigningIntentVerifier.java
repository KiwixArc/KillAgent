package pe.ong.chasca.killagent.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import pe.ong.chasca.killagent.config.AgentConfig;
import pe.ong.chasca.killagent.server.dto.SignedIntentEnvelope;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Verifies Ed25519 backend-signed {@link SignedIntentEnvelope} tokens and enforces
 * single-use anti-replay protection and parameter binding before hardware PIN prompts open.
 */
public final class SigningIntentVerifier {

    public static final String OPERATION_SIGN_DOCUMENT_DIGEST = "SIGN_DOCUMENT_DIGEST";
    public static final String OPERATION_SIGN_AUTH_CHALLENGE = "SIGN_AUTH_CHALLENGE";
    private static final String EXPECTED_ALGORITHM = "Ed25519";

    private final String backendIntentPublicKey;
    private final Clock clock;
    private final ObjectMapper objectMapper;
    private final ConcurrentHashMap<String, Instant> consumedIntents = new ConcurrentHashMap<>();

    public SigningIntentVerifier(AgentConfig config) {
        this(Objects.requireNonNull(config, "config must not be null").backendIntentPublicKey(), Clock.systemUTC());
    }

    public SigningIntentVerifier(AgentConfig config, Clock clock) {
        this(Objects.requireNonNull(config, "config must not be null").backendIntentPublicKey(), clock);
    }

    public SigningIntentVerifier(String backendIntentPublicKey, Clock clock) {
        this.backendIntentPublicKey = backendIntentPublicKey != null ? backendIntentPublicKey.trim() : "";
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
        this.objectMapper = new ObjectMapper();
    }

    /**
     * Exception thrown when a signing intent envelope fails Ed25519 verification,
     * expires, replays a previously consumed {@code intentId}, or mismatches request parameters.
     */
    public static final class InvalidSigningIntentException extends SecurityException {
        public InvalidSigningIntentException(String message) {
            super(message);
        }

        public InvalidSigningIntentException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /**
     * Verifies the Ed25519 signature, expiration timestamp, operation/parameter bindings,
     * and anti-replay uniqueness for the given {@link SignedIntentEnvelope}.
     *
     * @param envelope                  inbound signed intent envelope
     * @param expectedOperationType     {@code "SIGN_DOCUMENT_DIGEST"} or {@code "SIGN_AUTH_CHALLENGE"}
     * @param expectedDocumentHashNonce expected SHA-256 hex digest or auth challenge nonce
     * @param expectedSlotId            expected signature slot ID (required for {@code SIGN_DOCUMENT_DIGEST})
     * @return verified and decoded {@link SigningIntentPayload}
     * @throws InvalidSigningIntentException if any cryptographic, temporal, binding, or replay check fails
     */
    public SigningIntentPayload verifyAndConsume(
            SignedIntentEnvelope envelope,
            String expectedOperationType,
            String expectedDocumentHashNonce,
            String expectedSlotId
    ) {
        if (envelope == null) {
            throw new InvalidSigningIntentException("Falta la intención criptográfica firmada (signingIntent).");
        }
        if (backendIntentPublicKey.isBlank()) {
            throw new InvalidSigningIntentException(
                    "No existe una clave pública Ed25519 configurada (BACKEND_INTENT_PUBLIC_KEY) para verificar signingIntent."
            );
        }
        if (!EXPECTED_ALGORITHM.equals(envelope.algorithm())) {
            throw new InvalidSigningIntentException("Algoritmo de intención no soportado: " + envelope.algorithm());
        }
        if (envelope.payloadBase64Url() == null || envelope.payloadBase64Url().isBlank()
                || envelope.signatureBase64Url() == null || envelope.signatureBase64Url().isBlank()) {
            throw new InvalidSigningIntentException("La intención firmada está incompleta.");
        }

        verifyEd25519Signature(envelope.payloadBase64Url(), envelope.signatureBase64Url());
        SigningIntentPayload payload = decodePayload(envelope.payloadBase64Url());

        if (payload.intentId() == null || payload.intentId().isBlank()) {
            throw new InvalidSigningIntentException("La intención firmada carece de intentId.");
        }

        Instant expiresAt = parseAndValidateExpiration(payload.expiresAt());

        if (expectedOperationType == null || !expectedOperationType.equals(payload.operationType())) {
            throw new InvalidSigningIntentException(
                    "El operationType de la intención no coincide con la operación solicitada."
            );
        }

        validateBoundTargetFields(payload, expectedOperationType, expectedDocumentHashNonce, expectedSlotId);

        String cleanIntentId = payload.intentId().trim();
        Instant now = clock.instant();
        consumedIntents.entrySet().removeIf(entry -> !entry.getValue().isAfter(now));
        if (consumedIntents.putIfAbsent(cleanIntentId, expiresAt) != null) {
            throw new InvalidSigningIntentException("Intención de firma ya consumida (replay detectado).");
        }

        return payload;
    }

    private void verifyEd25519Signature(String payloadBase64Url, String signatureBase64Url) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(backendIntentPublicKey);
            byte[] sigBytes = Base64.getUrlDecoder().decode(signatureBase64Url.trim());

            KeyFactory kf = KeyFactory.getInstance(EXPECTED_ALGORITHM);
            PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(keyBytes));

            Signature verifier = Signature.getInstance(EXPECTED_ALGORITHM);
            verifier.initVerify(publicKey);
            verifier.update(payloadBase64Url.getBytes(StandardCharsets.UTF_8));
            if (!verifier.verify(sigBytes)) {
                throw new InvalidSigningIntentException("Firma Ed25519 de signingIntent inválida.");
            }
        } catch (InvalidSigningIntentException ex) {
            throw ex;
        } catch (Exception e) {
            throw new InvalidSigningIntentException(
                    "No se pudo verificar la firma Ed25519 de signingIntent: " + e.getMessage(),
                    e
            );
        }
    }

    private SigningIntentPayload decodePayload(String payloadBase64Url) {
        try {
            byte[] jsonBytes = Base64.getUrlDecoder().decode(payloadBase64Url);
            SigningIntentPayload payload = objectMapper.readValue(jsonBytes, SigningIntentPayload.class);
            if (payload == null) {
                throw new InvalidSigningIntentException("Payload de signingIntent vacío.");
            }
            return payload;
        } catch (InvalidSigningIntentException ex) {
            throw ex;
        } catch (Exception e) {
            throw new InvalidSigningIntentException("No se pudo decodificar el payload de signingIntent: " + e.getMessage(), e);
        }
    }

    private Instant parseAndValidateExpiration(String rawExpiresAt) {
        if (rawExpiresAt == null || rawExpiresAt.isBlank()) {
            throw new InvalidSigningIntentException("La intención firmada no especifica expiresAt.");
        }
        final Instant expiresAt;
        try {
            expiresAt = Instant.parse(rawExpiresAt.trim());
        } catch (Exception e) {
            throw new InvalidSigningIntentException("Formato expiresAt inválido en signingIntent.", e);
        }
        if (!expiresAt.isAfter(clock.instant())) {
            throw new InvalidSigningIntentException("La intención de firma ha expirado.");
        }
        return expiresAt;
    }

    private static void validateBoundTargetFields(
            SigningIntentPayload payload,
            String expectedOperationType,
            String expectedDocumentHashNonce,
            String expectedSlotId
    ) {
        if (payload.documentHash() == null || payload.documentHash().isBlank()
                || expectedDocumentHashNonce == null || expectedDocumentHashNonce.isBlank()) {
            throw new InvalidSigningIntentException("El hash/nonce de la intención firmada está ausente.");
        }

        String signedHash = payload.documentHash().trim();
        String requestedHash = expectedDocumentHashNonce.trim();

        if (OPERATION_SIGN_DOCUMENT_DIGEST.equals(expectedOperationType)) {
            if (!signedHash.equalsIgnoreCase(requestedHash)) {
                throw new InvalidSigningIntentException("El documentHash de la solicitud no coincide con el intent firmado.");
            }
            if (payload.slotId() == null || payload.slotId().isBlank()
                    || expectedSlotId == null || expectedSlotId.isBlank()
                    || !payload.slotId().trim().equals(expectedSlotId.trim())) {
                throw new InvalidSigningIntentException("El slotId de la solicitud no coincide con el intent firmado.");
            }
        } else if (OPERATION_SIGN_AUTH_CHALLENGE.equals(expectedOperationType)) {
            if (!signedHash.equals(requestedHash)) {
                throw new InvalidSigningIntentException("El nonce de la solicitud no coincide con el intent firmado.");
            }
        }
    }
}
