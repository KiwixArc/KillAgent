package pe.ong.chasca.killagent.update;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import pe.ong.chasca.killagent.config.AgentConfig;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;

class UpdateServiceTest {

    private HttpServer httpServer;

    @AfterEach
    void tearDown() {
        if (httpServer != null) {
            httpServer.stop(0);
        }
    }

    @Test
    void testChecksDownloadsAndVerifiesSignedManifestOverControlledServer(@TempDir Path tempDir) throws Exception {
        byte[] zipBytes = "PK-simulated-portable-zip-payload-v1.1.0".getBytes(StandardCharsets.UTF_8);
        String zipSha = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(zipBytes));

        KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        String privB64 = Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded());
        String pubB64 = Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());

        httpServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        int port = httpServer.getAddress().getPort();
        String baseUrl = "http://127.0.0.1:" + port;

        UpdateManifest baseManifest = new UpdateManifest(
                1,
                "KILLAgent",
                "stable",
                "1.1.0",
                "2026-11-22T18:00:00Z",
                false,
                "1.0.5",
                "Mejoras PKCS#11 y estabilidad WinSCard.",
                "https://github.com/KiwixArc/KillAgent/releases/tag/v1.1.0",
                Map.of(
                        "windows-x64-zip",
                        new UpdateManifest.ArtifactInfo(
                                "KILLAgent-1.1.0-windows-x64-portable.zip",
                                baseUrl + "/artifacts/KILLAgent-1.1.0-windows-x64-portable.zip",
                                zipSha,
                                zipBytes.length
                        )
                ),
                ""
        );
        String sig = UpdateVerifier.signCanonicalPayload(baseManifest.canonicalSigningPayload(), privB64);
        UpdateManifest signedManifest = new UpdateManifest(
                baseManifest.schemaVersion(),
                baseManifest.product(),
                baseManifest.channel(),
                baseManifest.version(),
                baseManifest.releaseDate(),
                baseManifest.mandatory(),
                baseManifest.minimumSupportedVersion(),
                baseManifest.releaseNotes(),
                baseManifest.releaseNotesUrl(),
                baseManifest.artifacts(),
                sig
        );
        byte[] manifestJson = new ObjectMapper().writeValueAsBytes(signedManifest);

        httpServer.createContext("/manifest.json", exchange -> {
            exchange.sendResponseHeaders(200, manifestJson.length);
            try (var os = exchange.getResponseBody()) {
                os.write(manifestJson);
            }
        });
        httpServer.createContext("/artifacts/KILLAgent-1.1.0-windows-x64-portable.zip", exchange -> {
            exchange.sendResponseHeaders(200, zipBytes.length);
            try (var os = exchange.getResponseBody()) {
                os.write(zipBytes);
            }
        });
        httpServer.start();

        AgentConfig config = new AgentConfig(
                "production",
                3000,
                "127.0.0.1",
                false,
                tempDir.resolve("loopback.p12").toString(),
                "changeit",
                Set.of("https://chaska.ong.pe"),
                "bit4ipki.dll",
                "idplug-pkcs11.dll",
                "auto",
                false,
                AgentConfig.DocumentDigestSignMode.PADES_DIGEST_INFO,
                true,
                true,
                "stable",
                baseUrl + "/manifest.json",
                6,
                pubB64,
                Set.of("127.0.0.1")
        );

        UpdateService service = new UpdateService(config, true);
        try {
            UpdateService.UpdateCheckResult result = service.checkForUpdates("1.0.0");
            assertEquals(UpdateService.CheckStatus.UPDATE_AVAILABLE, result.status());
            assertTrue(result.isUpdateAvailable());
            assertEquals("1.1.0", result.availableVersion());
            assertTrue(result.mandatory(), "1.0.0 < minimumSupportedVersion 1.0.5 must be flagged mandatory");
            assertTrue(result.signatureVerified());
            assertEquals("windows-x64-zip", result.selectedArtifactKey());

            AtomicBoolean progressCalled = new AtomicBoolean(false);
            Path downloaded = service.downloadAndVerifyArtifact(
                    result.manifest(),
                    result.selectedArtifactKey(),
                    (read, total) -> {
                        if (read > 0) progressCalled.set(true);
                    }
            );
            assertTrue(progressCalled.get());
            assertTrue(Files.isRegularFile(downloaded));
            assertArrayEquals(zipBytes, Files.readAllBytes(downloaded));
            Files.deleteIfExists(downloaded);

            // Already up-to-date when current == 1.1.0
            UpdateService.UpdateCheckResult upToDate = service.checkForUpdates("1.1.0");
            assertEquals(UpdateService.CheckStatus.UP_TO_DATE, upToDate.status());
            assertFalse(upToDate.isUpdateAvailable());
        } finally {
            service.stop();
        }
    }

    @Test
    void testRejectsCorruptedArtifactAndRemovesPartialFile(@TempDir Path tempDir) throws Exception {
        byte[] realBytes = "clean-payload".getBytes(StandardCharsets.UTF_8);
        String expectedSha = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(realBytes));

        httpServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        int port = httpServer.getAddress().getPort();
        String baseUrl = "http://127.0.0.1:" + port;

        byte[] corruptedBytes = "tampered-evil".getBytes(StandardCharsets.UTF_8);
        httpServer.createContext("/bad.zip", exchange -> {
            exchange.sendResponseHeaders(200, corruptedBytes.length);
            try (var os = exchange.getResponseBody()) {
                os.write(corruptedBytes);
            }
        });
        httpServer.start();

        AgentConfig config = new AgentConfig(
                "production",
                3000,
                "127.0.0.1",
                false,
                tempDir.resolve("loopback.p12").toString(),
                "changeit",
                Set.of("https://chaska.ong.pe"),
                "bit4ipki.dll",
                "idplug-pkcs11.dll",
                "auto",
                false,
                AgentConfig.DocumentDigestSignMode.PADES_DIGEST_INFO,
                true,
                true,
                "stable",
                baseUrl + "/manifest.json",
                6,
                "",
                Set.of("127.0.0.1")
        );

        UpdateManifest manifest = new UpdateManifest(
                1,
                "KILLAgent",
                "stable",
                "1.2.0",
                "2026-11-22T18:00:00Z",
                false,
                "1.0.0",
                "",
                "",
                Map.of("windows-x64-zip", new UpdateManifest.ArtifactInfo(
                        "KILLAgent-test-corrupt.zip",
                        baseUrl + "/bad.zip",
                        expectedSha,
                        realBytes.length
                )),
                ""
        );

        UpdateService service = new UpdateService(config, true);
        try {
            assertThrows(SecurityException.class, () ->
                    service.downloadAndVerifyArtifact(manifest, "windows-x64-zip", null)
            );
        } finally {
            service.stop();
        }
    }
}
