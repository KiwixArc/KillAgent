package pe.ong.chasca.killagent.crypto;

/**
 * Purpose of cryptographic operation mapped to DNIe KeyUsage bits.
 */
public enum CertificatePurpose {
    AUTHENTICATION, // KeyUsage: Digital Signature (no Non-Repudiation)
    SIGNATURE       // KeyUsage: Non-Repudiation / Content Commitment
}

