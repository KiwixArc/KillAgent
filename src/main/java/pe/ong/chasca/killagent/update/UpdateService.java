package pe.ong.chasca.killagent.update;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pe.ong.chasca.killagent.config.AgentConfig;
import pe.ong.chasca.killagent.config.AgentVersion;
import pe.ong.chasca.killagent.config.AppPaths;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/**
 * Checks, fetches, cryptographically validates, and downloads signed KILLAgent updates
 * without blocking daemon startup (< 500 ms SLA) or interrupting active smart card sessions.
 */
public class UpdateService {

    private static final Logger logger = LoggerFactory.getLogger(UpdateService.class);
    private static final int MAX_REDIRECT_HOPS = 5;
    private static final int MAX_MANIFEST_BYTES = 1_048_576;
    private static final long INITIAL_BACKGROUND_DELAY_SECONDS = 15L;

    public enum CheckStatus {
        DISABLED,
        UP_TO_DATE,
        UPDATE_AVAILABLE,
        ERROR
    }

    public record UpdateCheckResult(
            CheckStatus status,
            String currentVersion,
            String availableVersion,
            boolean mandatory,
            boolean signatureVerified,
            String selectedArtifactKey,
            UpdateManifest manifest,
            String message,
            Instant checkedAt
    ) {
        public boolean isUpdateAvailable() {
            return status == CheckStatus.UPDATE_AVAILABLE && manifest != null;
        }
    }

    @FunctionalInterface
    public interface DownloadProgressListener {
        void onProgress(long bytesDownloaded, long totalBytes);
    }

    private final AgentConfig config;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final boolean allowInsecureHttpForTests;
    private final ScheduledExecutorService scheduler;
    private volatile UpdateCheckResult lastResult;

    public UpdateService(AgentConfig config) {
        this(config, false);
    }

    UpdateService(AgentConfig config, boolean allowInsecureHttpForTests) {
        this.config = Objects.requireNonNull(config, "config must not be null");
        this.allowInsecureHttpForTests = allowInsecureHttpForTests;
        this.objectMapper = new ObjectMapper();
        this.httpClient = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "killagent-update-checker");
            t.setDaemon(true);
            return t;
        });
    }

    public UpdateCheckResult getLastResult() {
        return lastResult;
    }

    public void startBackgroundChecks(
            BooleanSupplier isBusySupplier,
            Consumer<UpdateCheckResult> onUpdateAvailable
    ) {
        if (!config.updateEnabled() || !config.updateAutoCheckEnabled()) {
            logger.info("Background update checks disabled by configuration.");
            return;
        }

        Runnable task = () -> {
            if (isBusySupplier != null && isBusySupplier.getAsBoolean()) {
                logger.debug("Skipping scheduled update check while smart card operation is in progress.");
                return;
            }
            UpdateCheckResult result = checkForUpdates();
            if (result.isUpdateAvailable() && onUpdateAvailable != null) {
                onUpdateAvailable.accept(result);
            }
        };

        long periodMinutes = Math.max(60L, config.updateCheckIntervalHours() * 60L);
        scheduler.scheduleWithFixedDelay(
                task,
                INITIAL_BACKGROUND_DELAY_SECONDS,
                periodMinutes * 60L,
                TimeUnit.SECONDS
        );
    }

    public UpdateCheckResult checkForUpdates() {
        return checkForUpdates(AgentVersion.getVersion());
    }

    UpdateCheckResult checkForUpdates(String installedVersionRaw) {
        Instant now = Instant.now();
        String currentStr = installedVersionRaw != null ? installedVersionRaw.trim() : "1.0.0";
        if (!config.updateEnabled()) {
            UpdateCheckResult disabled = new UpdateCheckResult(
                    CheckStatus.DISABLED,
                    currentStr,
                    null,
                    false,
                    false,
                    null,
                    null,
                    "Las actualizaciones automáticas están deshabilitadas en la configuración.",
                    now
            );
            this.lastResult = disabled;
            return disabled;
        }

        try {
            URI manifestUri = UpdateVerifier.validateDownloadUrl(
                    config.updateManifestUrl(),
                    config.updateAllowedHosts(),
                    allowInsecureHttpForTests
            );

            HttpResponse<byte[]> response = sendFollowingValidatedRedirects(
                    manifestUri,
                    HttpResponse.BodyHandlers.ofByteArray(),
                    Duration.ofSeconds(20)
            );
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                throw new IOException("HTTP " + response.statusCode() + " al consultar manifiesto de actualización.");
            }
            byte[] body = response.body();
            if (body == null || body.length == 0 || body.length > MAX_MANIFEST_BYTES) {
                throw new IOException("Manifiesto de actualización vacío o excede límite permitido.");
            }

            UpdateManifest manifest = objectMapper.readValue(new String(body, StandardCharsets.UTF_8), UpdateManifest.class);
            if (!"KILLAgent".equalsIgnoreCase(manifest.product())) {
                throw new SecurityException("Producto inesperado en manifiesto: " + manifest.product());
            }

            boolean signatureVerified = UpdateVerifier.verifyManifestSignature(manifest, config.updateSigningPublicKey());

            SemanticVersion current = SemanticVersion.parse(currentStr);
            SemanticVersion latest = SemanticVersion.parse(manifest.version());

            if (!latest.isNewerThan(current)) {
                UpdateCheckResult upToDate = new UpdateCheckResult(
                        CheckStatus.UP_TO_DATE,
                        current.toString(),
                        latest.toString(),
                        false,
                        signatureVerified,
                        null,
                        manifest,
                        "KILLAgent ya está en la última versión disponible (v" + current + ").",
                        now
                );
                this.lastResult = upToDate;
                return upToDate;
            }

            boolean mandatoryByMinFloor = false;
            if (manifest.minimumSupportedVersion() != null && !manifest.minimumSupportedVersion().isBlank()) {
                SemanticVersion minSupported = SemanticVersion.parse(manifest.minimumSupportedVersion());
                mandatoryByMinFloor = current.compareTo(minSupported) < 0;
            }

            String artifactKey = selectBestArtifactKey(manifest.artifacts());
            if (artifactKey == null) {
                throw new IOException("El manifiesto no contiene artefactos compatibles para Windows x64.");
            }

            UpdateManifest.ArtifactInfo artifact = manifest.artifacts().get(artifactKey);
            UpdateVerifier.validateDownloadUrl(
                    artifact.url(),
                    config.updateAllowedHosts(),
                    allowInsecureHttpForTests
            );

            UpdateCheckResult available = new UpdateCheckResult(
                    CheckStatus.UPDATE_AVAILABLE,
                    current.toString(),
                    latest.toString(),
                    manifest.mandatory() || mandatoryByMinFloor,
                    signatureVerified,
                    artifactKey,
                    manifest,
                    "Nueva versión v" + latest + " disponible.",
                    now
            );
            this.lastResult = available;
            logger.info("KILLAgent update detected: current=v{}, available=v{}, mandatory={}, signatureVerified={}",
                    current, latest, available.mandatory(), signatureVerified);
            return available;
        } catch (Exception e) {
            logger.warn("Update check failed: {}", e.getMessage());
            UpdateCheckResult err = new UpdateCheckResult(
                    CheckStatus.ERROR,
                    currentStr,
                    null,
                    false,
                    false,
                    null,
                    null,
                    e.getMessage() != null ? e.getMessage() : "Error al consultar actualizaciones.",
                    now
            );
            this.lastResult = err;
            return err;
        }
    }

    public Path downloadAndVerifyArtifact(
            UpdateManifest manifest,
            String artifactKey,
            DownloadProgressListener progressListener
    ) throws IOException {
        Objects.requireNonNull(manifest, "manifest must not be null");
        if (manifest.artifacts() == null || !manifest.artifacts().containsKey(artifactKey)) {
            throw new IOException("No se encontró el artefacto '" + artifactKey + "' en el manifiesto.");
        }

        UpdateManifest.ArtifactInfo artifact = manifest.artifacts().get(artifactKey);
        URI downloadUri = UpdateVerifier.validateDownloadUrl(
                artifact.url(),
                config.updateAllowedHosts(),
                allowInsecureHttpForTests
        );

        Path updatesDir = AppPaths.updatesDir();
        Files.createDirectories(updatesDir);

        String safeFileName = sanitizeFileName(
                artifact.fileName() != null && !artifact.fileName().isBlank()
                        ? artifact.fileName()
                        : "KILLAgent-" + manifest.version() + "-" + artifactKey
        );
        Path finalFile = updatesDir.resolve(safeFileName);
        Path partFile = updatesDir.resolve(safeFileName + ".part");
        Files.deleteIfExists(partFile);

        HttpResponse<InputStream> response = sendFollowingValidatedRedirects(
                downloadUri,
                HttpResponse.BodyHandlers.ofInputStream(),
                Duration.ofMinutes(5)
        );
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            try (InputStream ignored = response.body()) {
                throw new IOException("HTTP " + response.statusCode() + " descargando artefacto de actualización.");
            }
        }

        long totalBytes = artifact.sizeBytes() > 0
                ? artifact.sizeBytes()
                : response.headers().firstValueAsLong("Content-Length").orElse(-1L);

        try (InputStream in = response.body();
             OutputStream out = Files.newOutputStream(partFile)) {
            byte[] buffer = new byte[16_384];
            long downloaded = 0L;
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
                downloaded += read;
                if (progressListener != null) {
                    progressListener.onProgress(downloaded, totalBytes);
                }
            }
        } catch (Exception ex) {
            Files.deleteIfExists(partFile);
            if (ex instanceof IOException ioe) throw ioe;
            throw new IOException("Error durante descarga de actualización: " + ex.getMessage(), ex);
        }

        try {
            UpdateVerifier.verifyArtifactIntegrity(partFile, artifact);
        } catch (RuntimeException | IOException ex) {
            Files.deleteIfExists(partFile);
            throw ex;
        }

        Files.move(partFile, finalFile, StandardCopyOption.REPLACE_EXISTING);
        logger.info("Update artifact verified (SHA-256) and stored at {}", finalFile);
        return finalFile;
    }

    public void stop() {
        scheduler.shutdownNow();
    }

    private String selectBestArtifactKey(Map<String, UpdateManifest.ArtifactInfo> artifacts) {
        if (artifacts == null || artifacts.isEmpty()) {
            return null;
        }
        UpdateInstaller.LaunchMode mode = UpdateInstaller.detectLaunchMode();
        if (mode == UpdateInstaller.LaunchMode.PORTABLE_EXE && artifacts.containsKey("windows-x64-zip")) {
            return "windows-x64-zip";
        }
        if (artifacts.containsKey("windows-x64-msi")) {
            return "windows-x64-msi";
        }
        if (artifacts.containsKey("windows-x64-zip")) {
            return "windows-x64-zip";
        }
        if (artifacts.containsKey("universal-jar")) {
            return "universal-jar";
        }
        return artifacts.keySet().iterator().next();
    }

    private <T> HttpResponse<T> sendFollowingValidatedRedirects(
            URI initialUri,
            HttpResponse.BodyHandler<T> handler,
            Duration requestTimeout
    ) throws IOException {
        URI currentUri = initialUri;
        for (int hop = 0; hop <= MAX_REDIRECT_HOPS; hop++) {
            HttpRequest request = HttpRequest.newBuilder(currentUri)
                    .GET()
                    .timeout(requestTimeout)
                    .header("User-Agent", "KILLAgent/" + AgentVersion.getVersion() + " (Ch'aska Zero Trust)")
                    .header("Accept", "application/json, application/octet-stream")
                    .build();

            final HttpResponse<T> response;
            try {
                response = httpClient.send(request, handler);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                throw new IOException("Solicitud de actualización interrumpida.", ie);
            }

            int status = response.statusCode();
            if (status == 301 || status == 302 || status == 303 || status == 307 || status == 308) {
                closeStreamIfNeeded(response.body());
                String location = response.headers().firstValue("Location").orElse("");
                if (location.isBlank()) {
                    throw new IOException("Redirección HTTP " + status + " sin cabecera Location.");
                }
                URI resolved = currentUri.resolve(location.trim());
                currentUri = UpdateVerifier.validateDownloadUrl(
                        resolved.toString(),
                        config.updateAllowedHosts(),
                        allowInsecureHttpForTests
                );
                continue;
            }
            return response;
        }
        throw new IOException("Demasiadas redirecciones al descargar la actualización.");
    }

    private static void closeStreamIfNeeded(Object body) {
        if (body instanceof InputStream is) {
            try {
                is.close();
            } catch (IOException ignored) {
            }
        }
    }

    private static String sanitizeFileName(String raw) {
        String base = PathsBaseName(raw);
        return base.replaceAll("[^0-9A-Za-z._-]", "_");
    }

    private static String PathsBaseName(String raw) {
        int slash = Math.max(raw.lastIndexOf('/'), raw.lastIndexOf('\\'));
        return slash >= 0 ? raw.substring(slash + 1) : raw;
    }
}
