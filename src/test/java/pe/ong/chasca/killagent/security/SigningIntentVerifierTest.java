package pe.ong.chasca.killagent.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import pe.ong.chasca.killagent.server.dto.SignedIntentEnvelope;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class SigningIntentVerifierTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String SAMPLE_HASH =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    @Test
    void testValidDocumentDigestAndAuthIntentsVerifyAndPreventReplay() throws Exception {
        KeyPair kp = generateEd25519KeyPair();
        String pubB64 = Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());

        AtomicReference<Instant> currentNow = new AtomicReference<>(Instant.parse("2026-11-25T20:00:00Z"));
        Clock mutableClock = new Clock() {
            @Override
            public ZoneOffset getZone() {
                return ZoneOffset.UTC;
            }

            @Override
            public Clock withZone(java.time.ZoneId zone) {
                return this;
            }

            @Override
            public Instant instant() {
                return currentNow.get();
            }
        };

        SigningIntentVerifier verifier = new SigningIntentVerifier(pubB64, mutableClock);

        SigningIntentPayload docPayload = new SigningIntentPayload(
                "intent-doc-1",
                SigningIntentVerifier.OPERATION_SIGN_DOCUMENT_DIGEST,
                "slot-uuid-001",
                SAMPLE_HASH.toUpperCase(),
                "Contrato Oficial 2026.pdf",
                "GERENTE_GENERAL",
                "71234567",
                "2026-11-25T20:05:00Z"
        );
        SignedIntentEnvelope docEnvelope = signPayload(docPayload, kp.getPrivate(), "kid-1");

        // Case-insensitive hex match for documentHash must succeed
        SigningIntentPayload verifiedDoc = verifier.verifyAndConsume(
                docEnvelope,
                SigningIntentVerifier.OPERATION_SIGN_DOCUMENT_DIGEST,
                SAMPLE_HASH.toLowerCase(),
                "slot-uuid-001"
        );
        assertEquals("intent-doc-1", verifiedDoc.intentId());
        assertEquals("Contrato Oficial 2026.pdf", verifiedDoc.documentTitle());
        assertEquals("GERENTE_GENERAL", verifiedDoc.signerRole());

        // Replaying the exact same intentId must fail
        assertThrows(SigningIntentVerifier.InvalidSigningIntentException.class, () ->
                verifier.verifyAndConsume(
                        docEnvelope,
                        SigningIntentVerifier.OPERATION_SIGN_DOCUMENT_DIGEST,
                        SAMPLE_HASH.toLowerCase(),
                        "slot-uuid-001"
                ));

        // Valid auth challenge intent (exact nonce match)
        SigningIntentPayload authPayload = new SigningIntentPayload(
                "intent-auth-1",
                SigningIntentVerifier.OPERATION_SIGN_AUTH_CHALLENGE,
                null,
                "NonceExactValue_123",
                null,
                null,
                "71234567",
                "2026-11-25T20:05:00Z"
        );
        SignedIntentEnvelope authEnvelope = signPayload(authPayload, kp.getPrivate(), "kid-1");
        SigningIntentPayload verifiedAuth = verifier.verifyAndConsume(
                authEnvelope,
                SigningIntentVerifier.OPERATION_SIGN_AUTH_CHALLENGE,
                "NonceExactValue_123",
                null
        );
        assertEquals("intent-auth-1", verifiedAuth.intentId());

        // Advance clock past expiration so expired entries get purged cleanly while new intent succeeds
        currentNow.set(Instant.parse("2026-11-25T20:06:00Z"));
        SigningIntentPayload freshPayload = new SigningIntentPayload(
                "intent-doc-2",
                SigningIntentVerifier.OPERATION_SIGN_DOCUMENT_DIGEST,
                "slot-uuid-002",
                SAMPLE_HASH,
                "Adenda 2026.pdf",
                "SIGNER",
                "71234567",
                "2026-11-25T20:10:00Z"
        );
        SignedIntentEnvelope freshEnvelope = signPayload(freshPayload, kp.getPrivate(), "kid-1");
        assertNotNull(verifier.verifyAndConsume(
                freshEnvelope,
                SigningIntentVerifier.OPERATION_SIGN_DOCUMENT_DIGEST,
                SAMPLE_HASH,
                "slot-uuid-002"
        ));
    }

    @Test
    void testRejectsTamperedSignatureWrongAlgExpiredAndE6Substitutions() throws Exception {
        KeyPair kp = generateEd25519KeyPair();
        String pubB64 = Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());
        Instant fixedNow = Instant.parse("2026-11-25T20:00:00Z");
        SigningIntentVerifier verifier = new SigningIntentVerifier(pubB64, Clock.fixed(fixedNow, ZoneOffset.UTC));

        SigningIntentPayload validPayload = new SigningIntentPayload(
                "intent-e6-1",
                SigningIntentVerifier.OPERATION_SIGN_DOCUMENT_DIGEST,
                "slot-legit",
                SAMPLE_HASH,
                "Documento Legitimo.pdf",
                "SIGNER",
                "71234567",
                "2026-11-25T20:05:00Z"
        );
        SignedIntentEnvelope validEnvelope = signPayload(validPayload, kp.getPrivate(), "kid-1");

        // 1. Wrong algorithm
        SignedIntentEnvelope wrongAlg = new SignedIntentEnvelope(
                validEnvelope.payloadBase64Url(),
                validEnvelope.signatureBase64Url(),
                "RS256",
                "kid-1"
        );
        assertThrows(SigningIntentVerifier.InvalidSigningIntentException.class, () ->
                verifier.verifyAndConsume(wrongAlg, SigningIntentVerifier.OPERATION_SIGN_DOCUMENT_DIGEST, SAMPLE_HASH, "slot-legit"));

        // 2. Tampered signature
        byte[] sigBytes = Base64.getUrlDecoder().decode(validEnvelope.signatureBase64Url());
        sigBytes[0] ^= 0x55;
        SignedIntentEnvelope tamperedSig = new SignedIntentEnvelope(
                validEnvelope.payloadBase64Url(),
                Base64.getUrlEncoder().withoutPadding().encodeToString(sigBytes),
                "Ed25519",
                "kid-1"
        );
        assertThrows(SigningIntentVerifier.InvalidSigningIntentException.class, () ->
                verifier.verifyAndConsume(tamperedSig, SigningIntentVerifier.OPERATION_SIGN_DOCUMENT_DIGEST, SAMPLE_HASH, "slot-legit"));

        // 3. E6 attack: documentHash substitution in outer request
        assertThrows(SigningIntentVerifier.InvalidSigningIntentException.class, () ->
                verifier.verifyAndConsume(
                        validEnvelope,
                        SigningIntentVerifier.OPERATION_SIGN_DOCUMENT_DIGEST,
                        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                        "slot-legit"
                ));

        // 4. E6 attack: slotId substitution in outer request
        assertThrows(SigningIntentVerifier.InvalidSigningIntentException.class, () ->
                verifier.verifyAndConsume(
                        validEnvelope,
                        SigningIntentVerifier.OPERATION_SIGN_DOCUMENT_DIGEST,
                        SAMPLE_HASH,
                        "slot-attacker"
                ));

        // 5. OperationType mismatch
        assertThrows(SigningIntentVerifier.InvalidSigningIntentException.class, () ->
                verifier.verifyAndConsume(
                        validEnvelope,
                        SigningIntentVerifier.OPERATION_SIGN_AUTH_CHALLENGE,
                        SAMPLE_HASH,
                        null
                ));

        // 6. Expired intent
        SigningIntentPayload expiredPayload = new SigningIntentPayload(
                "intent-expired",
                SigningIntentVerifier.OPERATION_SIGN_DOCUMENT_DIGEST,
                "slot-legit",
                SAMPLE_HASH,
                "Documento Expirado.pdf",
                "SIGNER",
                "71234567",
                "2026-11-25T19:59:59Z"
        );
        SignedIntentEnvelope expiredEnvelope = signPayload(expiredPayload, kp.getPrivate(), "kid-1");
        assertThrows(SigningIntentVerifier.InvalidSigningIntentException.class, () ->
                verifier.verifyAndConsume(
                        expiredEnvelope,
                        SigningIntentVerifier.OPERATION_SIGN_DOCUMENT_DIGEST,
                        SAMPLE_HASH,
                        "slot-legit"
                ));

        // 7. Missing public key fails closed
        SigningIntentVerifier keylessVerifier = new SigningIntentVerifier("", Clock.fixed(fixedNow, ZoneOffset.UTC));
        assertThrows(SigningIntentVerifier.InvalidSigningIntentException.class, () ->
                keylessVerifier.verifyAndConsume(
                        validEnvelope,
                        SigningIntentVerifier.OPERATION_SIGN_DOCUMENT_DIGEST,
                        SAMPLE_HASH,
                        "slot-legit"
                ));
    }

    private static KeyPair generateEd25519KeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
        return kpg.generateKeyPair();
    }

    private static SignedIntentEnvelope signPayload(
            SigningIntentPayload payload,
            PrivateKey privateKey,
            String keyId
    ) throws Exception {
        byte[] jsonBytes = MAPPER.writeValueAsBytes(payload);
        String payloadB64Url = Base64.getUrlEncoder().withoutPadding().encodeToString(jsonBytes);

        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(privateKey);
        signer.update(payloadB64Url.getBytes(StandardCharsets.UTF_8));
        String sigB64Url = Base64.getUrlEncoder().withoutPadding().encodeToString(signer.sign());

        return new SignedIntentEnvelope(payloadB64Url, sigB64Url, "Ed25519", keyId);
    }
}
