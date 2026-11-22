package pe.ong.chasca.killagent.crypto;

/**
 * Result of signing a document digest (PAdES format).
 */
public record DocumentDigestResult(
        String slotId,
        String certificateDni,
        String documentHash,
        String signatureValue,
        String signerSubjectDn,
        String certificateSerialNumber,
        String clientCertificatePem
) {}

