package pe.ong.chasca.killagent.update;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

/**
 * Signed release update manifest published alongside KILLAgent GitHub Releases
 * or institutional HTTPS update endpoints.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record UpdateManifest(
        @JsonProperty("schemaVersion") int schemaVersion,
        @JsonProperty("product") String product,
        @JsonProperty("channel") String channel,
        @JsonProperty("version") String version,
        @JsonProperty("releaseDate") String releaseDate,
        @JsonProperty("mandatory") boolean mandatory,
        @JsonProperty("minimumSupportedVersion") String minimumSupportedVersion,
        @JsonProperty("releaseNotes") String releaseNotes,
        @JsonProperty("releaseNotesUrl") String releaseNotesUrl,
        @JsonProperty("artifacts") Map<String, ArtifactInfo> artifacts,
        @JsonProperty("signature") String signature
) {
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record ArtifactInfo(
            @JsonProperty("fileName") String fileName,
            @JsonProperty("url") String url,
            @JsonProperty("sha256") String sha256,
            @JsonProperty("sizeBytes") long sizeBytes
    ) {
    }

    /**
     * Produces the deterministic UTF-8 canonical payload covered by the Ed25519 signature.
     * Both publisher tooling (scripts/ManifestSigner.java) and client verifier compute this exact string.
     */
    public String canonicalSigningPayload() {
        StringBuilder sb = new StringBuilder(256);
        sb.append("schemaVersion=").append(schemaVersion).append('\n');
        sb.append("product=").append(nullToEmpty(product)).append('\n');
        sb.append("channel=").append(nullToEmpty(channel)).append('\n');
        sb.append("version=").append(nullToEmpty(version)).append('\n');
        sb.append("mandatory=").append(mandatory).append('\n');
        sb.append("minimumSupportedVersion=").append(nullToEmpty(minimumSupportedVersion)).append('\n');

        TreeMap<String, ArtifactInfo> sorted = new TreeMap<>();
        if (artifacts != null) {
            sorted.putAll(artifacts);
        }
        for (Map.Entry<String, ArtifactInfo> entry : sorted.entrySet()) {
            ArtifactInfo info = entry.getValue();
            if (info == null) continue;
            sb.append("artifact.").append(entry.getKey()).append('=')
                    .append(nullToEmpty(info.fileName())).append('|')
                    .append(nullToEmpty(info.url())).append('|')
                    .append(nullToEmpty(info.sha256()).toLowerCase(Locale.ROOT)).append('|')
                    .append(info.sizeBytes()).append('\n');
        }
        return sb.toString();
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value.trim();
    }
}
