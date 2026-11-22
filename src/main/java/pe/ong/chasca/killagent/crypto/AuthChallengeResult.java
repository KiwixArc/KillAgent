package pe.ong.chasca.killagent.crypto;

import java.util.Map;

/**
 * Result of signing an authentication challenge nonce.
 */
public record AuthChallengeResult(
        String nonce,
        String signedNonce,
        String clientCertificatePem,
        Map<String, String> metadata
) {}

