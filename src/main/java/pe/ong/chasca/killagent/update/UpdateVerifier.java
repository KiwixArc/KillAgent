package pe.ong.chasca.killagent.update;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Set;

/**
 * Cryptographic and transport security verifier for KILLAgent updates:
 * - Enforces HTTPS origin & host whitelist on manifest, redirect, and binary URLs
 * - Verifies Ed25519 manifest signatures when a public key is pinned
 * - Verifies exact byte length and constant-time SHA-256 integrity of downloaded packages
 */
public final class UpdateVerifier {

    private UpdateVerifier() {
    }

    public static URI validateDownloadUrl(
            String rawUrl,
            Set<String> allowedHosts,
            boolean allowInsecureHttpForLocalTests
    ) {
        if (rawUrl == null || rawUrl.isBlank()) {
            throw new SecurityException("La URL de actualización no puede estar vacía.");
        }

        final URI uri;
        try {
            uri = URI.create(rawUrl.trim());
        } catch (Exception e) {
            throw new SecurityException("URL de actualización inválida: " + rawUrl, e);
        }

        String scheme = uri.getScheme() != null ? uri.getScheme().toLowerCase(Locale.ROOT) : "";
        String host = uri.getHost() != null ? uri.getHost().toLowerCase(Locale.ROOT) : "";

        if (host.isBlank() || uri.getUserInfo() != null) {
            throw new SecurityException("URL de actualización rechazada por política de seguridad: " + rawUrl);
        }

        boolean isLoopback = "127.0.0.1".equals(host) || "localhost".equals(host);
        if ("https".equals(scheme)) {
            // Valid encrypted transport
        } else if (allowInsecureHttpForLocalTests && "http".equals(scheme) && isLoopback) {
            // Permitted solely for automated unit/integration tests against loopback HttpServer
        } else {
            throw new SecurityException("Las actualizaciones solo se permiten sobre transporte cifrado HTTPS: " + rawUrl);
        }

        if (allowedHosts != null && !allowedHosts.isEmpty()) {
            boolean permitted = false;
            for (String candidate : allowedHosts) {
                if (candidate == null || candidate.isBlank()) {
                    continue;
                }
                String normalizedAllowed = candidate.trim().toLowerCase(Locale.ROOT);
                if (host.equals(normalizedAllowed) || host.endsWith("." + normalizedAllowed)) {
                    permitted = true;
                    break;
                }
            }
            if (!permitted) {
                throw new SecurityException(
                        "El host '" + host + "' no está autorizado en UPDATE_ALLOWED_HOSTS."
                );
            }
        }

        return uri;
    }

    /**
     * Verifies the Ed25519 signature over {@link UpdateManifest#canonicalSigningPayload()} if a public key is pinned.
     *
     * @return {@code true} if signature was cryptographically verified with the pinned Ed25519 key;
     *         {@code false} if no public key is pinned (relies on TLS + SHA-256 verification).
     * @throws SecurityException if a public key is pinned and the signature is missing or invalid.
     */
    public static boolean verifyManifestSignature(UpdateManifest manifest, String base64SpkiPublicKey) {
        if (base64SpkiPublicKey == null || base64SpkiPublicKey.isBlank()) {
            return false;
        }
        if (manifest == null || manifest.signature() == null || manifest.signature().isBlank()) {
            throw new SecurityException(
                    "El manifiesto de actualización no contiene firma Ed25519 y UPDATE_SIGNING_PUBLIC_KEY está activa."
            );
        }

        try {
            byte[] keyBytes = Base64.getDecoder().decode(base64SpkiPublicKey.trim());
            byte[] sigBytes = Base64.getDecoder().decode(manifest.signature().trim());

            KeyFactory kf = KeyFactory.getInstance("Ed25519");
            PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(keyBytes));

            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(publicKey);
            verifier.update(manifest.canonicalSigningPayload().getBytes(StandardCharsets.UTF_8));
            if (!verifier.verify(sigBytes)) {
                throw new SecurityException("Firma Ed25519 del manifiesto de actualización inválida.");
            }
            return true;
        } catch (SecurityException se) {
            throw se;
        } catch (Exception e) {
            throw new SecurityException("No se pudo verificar la firma Ed25519 del manifiesto: " + e.getMessage(), e);
        }
    }

    public static String signCanonicalPayload(String payload, String base64Pkcs8PrivateKey) {
        try {
            byte[] privBytes = Base64.getDecoder().decode(base64Pkcs8PrivateKey.trim());
            KeyFactory kf = KeyFactory.getInstance("Ed25519");
            PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(privBytes));

            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(privateKey);
            signer.update(payload.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(signer.sign());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to sign update manifest payload with Ed25519", e);
        }
    }

    public static String computeSha256Hex(Path file) throws IOException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[16_384];
            try (InputStream is = Files.newInputStream(file)) {
                int read;
                while ((read = is.read(buffer)) != -1) {
                    digest.update(buffer, 0, read);
                }
            }
            return HexFormat.of().formatHex(digest.digest());
        } catch (IOException ioe) {
            throw ioe;
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 MessageDigest unavailable", e);
        }
    }

    public static void verifyArtifactIntegrity(Path file, UpdateManifest.ArtifactInfo artifact) throws IOException {
        if (file == null || !Files.isRegularFile(file)) {
            throw new SecurityException("Archivo de actualización inexistente en disco.");
        }
        if (artifact == null) {
            throw new SecurityException("Metadatos de artefacto faltantes en el manifiesto.");
        }

        if (artifact.sizeBytes() > 0) {
            long actualSize = Files.size(file);
            if (actualSize != artifact.sizeBytes()) {
                throw new SecurityException(
                        "Tamaño de archivo inesperado para actualización (esperado="
                                + artifact.sizeBytes() + " bytes, recibido=" + actualSize + " bytes)."
                );
            }
        }

        String expectedSha = artifact.sha256() != null ? artifact.sha256().trim().toLowerCase(Locale.ROOT) : "";
        if (!expectedSha.matches("^[0-9a-f]{64}$")) {
            throw new SecurityException("Hash SHA-256 inválido o ausente en manifiesto de actualización.");
        }

        String actualSha = computeSha256Hex(file);
        if (!MessageDigest.isEqual(
                expectedSha.getBytes(StandardCharsets.UTF_8),
                actualSha.getBytes(StandardCharsets.UTF_8))) {
            throw new SecurityException(
                    "Integridad SHA-256 comprometida. Esperado=" + expectedSha + ", calculado=" + actualSha
            );
        }
    }
}
