package pe.ong.chasca.killagent.crypto;

import pe.ong.chasca.killagent.server.dto.ErrorCode;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

/**
 * Cryptographic helper for RFC 8017 (PKCS#1 v2.2) ASN.1 DER DigestInfo encoding
 * and strict hexadecimal validation for SHA-256 digests and authentication nonces.
 */
public final class RsaDigestInfoHelper {

    /**
     * ASN.1 DER prefix for SHA-256 DigestInfo (OID 2.16.840.1.101.3.4.2.1 with NULL parameters + 32-byte OCTET STRING):
     * SEQUENCE (49 bytes) {
     *   SEQUENCE (13 bytes) {
     *     OBJECT IDENTIFIER 2.16.840.1.101.3.4.2.1 (SHA-256)
     *     NULL
     *   }
     *   OCTET STRING (32 bytes)
     * }
     */
    private static final byte[] SHA256_DIGEST_INFO_PREFIX = new byte[]{
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09,
            0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
            0x05, 0x00, 0x04, 0x20
    };

    private static final int SHA256_BYTE_LENGTH = 32;
    private static final int SHA256_HEX_LENGTH = 64;

    private RsaDigestInfoHelper() {}

    /**
     * Validates and parses a 64-character hexadecimal SHA-256 digest into 32 raw bytes.
     */
    public static byte[] decodeSha256Hex(String sha256Hex) throws CryptoOperationException {
        if (sha256Hex == null || sha256Hex.trim().length() != SHA256_HEX_LENGTH) {
            throw new CryptoOperationException(
                    ErrorCode.MALFORMED_REQUEST,
                    "El hash del documento debe ser un digest SHA-256 hexadecimal válido de 64 caracteres."
            );
        }
        try {
            byte[] digest = HexFormat.of().parseHex(sha256Hex.trim());
            if (digest.length != SHA256_BYTE_LENGTH) {
                throw new IllegalArgumentException("Unexpected digest byte length");
            }
            return digest;
        } catch (IllegalArgumentException e) {
            throw new CryptoOperationException(
                    ErrorCode.MALFORMED_REQUEST,
                    "El hash del documento contiene caracteres no hexadecimales inválidos.",
                    null,
                    e
            );
        }
    }

    /**
     * Encapsulates a raw 32-byte SHA-256 digest into a 51-byte DER DigestInfo structure
     * suitable for signing with NONEwithRSA (PKCS#11 CKM_RSA_PKCS).
     */
    public static byte[] buildSha256DigestInfo(byte[] sha256Digest) {
        if (sha256Digest == null || sha256Digest.length != SHA256_BYTE_LENGTH) {
            throw new IllegalArgumentException("SHA-256 digest must be exactly 32 bytes.");
        }
        byte[] digestInfo = new byte[SHA256_DIGEST_INFO_PREFIX.length + SHA256_BYTE_LENGTH];
        System.arraycopy(SHA256_DIGEST_INFO_PREFIX, 0, digestInfo, 0, SHA256_DIGEST_INFO_PREFIX.length);
        System.arraycopy(sha256Digest, 0, digestInfo, SHA256_DIGEST_INFO_PREFIX.length, SHA256_BYTE_LENGTH);
        return digestInfo;
    }

    /**
     * Resolves an incoming authentication challenge nonce into bytes to be signed with SHA256withRSA.
     * If the nonce is valid even-length hex (>= 32 chars), decodes hex bytes; otherwise signs UTF-8 bytes safely.
     */
    public static byte[] decodeChallengeNonce(String nonce) throws CryptoOperationException {
        if (nonce == null || nonce.isBlank()) {
            throw new CryptoOperationException(
                    ErrorCode.MALFORMED_REQUEST,
                    "El reto criptográfico (nonce) no puede estar vacío."
            );
        }
        String trimmed = nonce.trim();
        if (trimmed.length() >= 32 && (trimmed.length() % 2 == 0) && isHex(trimmed)) {
            return HexFormat.of().parseHex(trimmed);
        }
        return trimmed.getBytes(StandardCharsets.UTF_8);
    }

    private static boolean isHex(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean hexDigit = (c >= '0' && c <= '9')
                    || (c >= 'a' && c <= 'f')
                    || (c >= 'A' && c <= 'F');
            if (!hexDigit) return false;
        }
        return true;
    }
}

