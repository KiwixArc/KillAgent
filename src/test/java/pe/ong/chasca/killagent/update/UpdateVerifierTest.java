package pe.ong.chasca.killagent.update;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class UpdateVerifierTest {

    @Test
    void testHttpsAndAllowedHostsPolicyEnforced() {
        Set<String> allowed = Set.of("github.com", "objects.githubusercontent.com");

        assertDoesNotThrow(() -> UpdateVerifier.validateDownloadUrl(
                "https://github.com/KiwixArc/KillAgent/releases/latest/download/update-manifest.json",
                allowed,
                false
        ));
        assertDoesNotThrow(() -> UpdateVerifier.validateDownloadUrl(
                "https://release-assets.githubusercontent.com/file.msi",
                Set.of("github.com", "release-assets.githubusercontent.com"),
                false
        ));

        // Reject plaintext HTTP and untrusted domains
        assertThrows(SecurityException.class, () -> UpdateVerifier.validateDownloadUrl(
                "http://github.com/KiwixArc/KillAgent/releases/download/v1.0.1/update-manifest.json",
                allowed,
                false
        ));
        assertThrows(SecurityException.class, () -> UpdateVerifier.validateDownloadUrl(
                "https://github.com.evil.example/update-manifest.json",
                allowed,
                false
        ));
        assertThrows(SecurityException.class, () -> UpdateVerifier.validateDownloadUrl(
                "https://user:pass@github.com/update-manifest.json",
                allowed,
                false
        ));
    }

    @Test
    void testSha256AndByteSizeIntegrityVerification(@TempDir Path tempDir) throws Exception {
        Path file = tempDir.resolve("KILLAgent-1.0.1.msi");
        byte[] payload = "simulated-msi-binary-content-2026".getBytes(StandardCharsets.UTF_8);
        Files.write(file, payload);

        String sha256 = UpdateVerifier.computeSha256Hex(file);
        UpdateManifest.ArtifactInfo validInfo = new UpdateManifest.ArtifactInfo(
                "KILLAgent-1.0.1.msi",
                "https://github.com/KiwixArc/KillAgent/releases/download/v1.0.1/KILLAgent-1.0.1.msi",
                sha256,
                payload.length
        );
        assertDoesNotThrow(() -> UpdateVerifier.verifyArtifactIntegrity(file, validInfo));

        UpdateManifest.ArtifactInfo badHash = new UpdateManifest.ArtifactInfo(
                validInfo.fileName(),
                validInfo.url(),
                "0".repeat(64),
                payload.length
        );
        assertThrows(SecurityException.class, () -> UpdateVerifier.verifyArtifactIntegrity(file, badHash));

        UpdateManifest.ArtifactInfo badSize = new UpdateManifest.ArtifactInfo(
                validInfo.fileName(),
                validInfo.url(),
                sha256,
                payload.length + 10
        );
        assertThrows(SecurityException.class, () -> UpdateVerifier.verifyArtifactIntegrity(file, badSize));
    }

    @Test
    void testEd25519ManifestSignatureSignAndVerify() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        String privB64 = Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded());
        String pubB64 = Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());

        UpdateManifest unsigned = new UpdateManifest(
                1,
                "KILLAgent",
                "stable",
                "1.0.1",
                "2026-11-22T16:00:00Z",
                false,
                "1.0.0",
                "Security updates",
                "https://github.com/KiwixArc/KillAgent/releases/tag/v1.0.1",
                Map.of("windows-x64-msi", new UpdateManifest.ArtifactInfo(
                        "KILLAgent-1.0.1.msi",
                        "https://github.com/KiwixArc/KillAgent/releases/download/v1.0.1/KILLAgent-1.0.1.msi",
                        "a".repeat(64),
                        1024L
                )),
                ""
        );

        // Unpinned key accepts unsigned manifests; pinned key rejects unsigned manifests
        assertFalse(UpdateVerifier.verifyManifestSignature(unsigned, ""));
        assertThrows(SecurityException.class, () -> UpdateVerifier.verifyManifestSignature(unsigned, pubB64));

        String sig = UpdateVerifier.signCanonicalPayload(unsigned.canonicalSigningPayload(), privB64);
        UpdateManifest signed = new UpdateManifest(
                unsigned.schemaVersion(),
                unsigned.product(),
                unsigned.channel(),
                unsigned.version(),
                unsigned.releaseDate(),
                unsigned.mandatory(),
                unsigned.minimumSupportedVersion(),
                unsigned.releaseNotes(),
                unsigned.releaseNotesUrl(),
                unsigned.artifacts(),
                sig
        );
        assertTrue(UpdateVerifier.verifyManifestSignature(signed, pubB64));

        // Tampering with version breaks Ed25519 verification
        UpdateManifest tampered = new UpdateManifest(
                signed.schemaVersion(),
                signed.product(),
                signed.channel(),
                "9.9.9",
                signed.releaseDate(),
                signed.mandatory(),
                signed.minimumSupportedVersion(),
                signed.releaseNotes(),
                signed.releaseNotesUrl(),
                signed.artifacts(),
                signed.signature()
        );
        assertThrows(SecurityException.class, () -> UpdateVerifier.verifyManifestSignature(tampered, pubB64));
    }
}
