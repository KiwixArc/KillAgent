package pe.ong.chasca.killagent.security;

import pe.ong.chasca.killagent.config.AgentConfig;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Strict RFC 6454 Web Origin validator protecting the local WebSocket loopback server
 * against Cross-Site WebSocket Hijacking (CSWSH) and DNS/subdomain spoofing attacks.
 * <p>
 * <strong>Zero Trust Security Invariants:</strong>
 * <ul>
 *     <li>Missing, blank, or {@code "null"} origins (such as sandboxed iframes or {@code file://} pages)
 *     are unconditionally rejected.</li>
 *     <li>Wildcard {@code "*"} is honored solely when {@link AgentConfig#isDevelopment()} is {@code true}
 *     (production configs containing {@code "*"} are rejected at {@code AgentConfig} construction).</li>
 *     <li>Supports exact canonical origins, HTTPS subdomain wildcards (e.g., {@code https://*.pages.dev}
 *     pinned to effective port {@code 443} with non-empty dot-bounded labels), and loopback arbitrary-port
 *     wildcards strictly restricted to {@code localhost} and {@code 127.0.0.1} (e.g., {@code http://localhost:*}).</li>
 *     <li>Origins containing userinfo, non-root paths, query strings, fragments, or non-HTTP(S) schemes are rejected.</li>
 * </ul>
 */
public final class OriginValidator {

    private record ParsedOrigin(String scheme, String host, int effectivePort) {}

    private record WildcardPattern(String scheme, String domainSuffix, boolean anyPort) {}

    private final boolean allowWildcardInDev;
    private final Set<String> normalizedAllowedOrigins;
    private final List<WildcardPattern> wildcardPatterns;

    /**
     * Compiles exact canonical origins and bounded wildcard matchers from {@link AgentConfig#allowedOrigins()}.
     *
     * @param config active runtime configuration providing environment mode and {@code ALLOWED_ORIGINS}
     */
    public OriginValidator(AgentConfig config) {
        this.allowWildcardInDev = config.isDevelopment() && config.allowedOrigins().contains("*");
        Set<String> exact = new LinkedHashSet<>();
        List<WildcardPattern> patterns = new ArrayList<>();

        for (String raw : config.allowedOrigins()) {
            if (raw == null || raw.isBlank() || "*".equals(raw.trim())) {
                continue;
            }
            String trimmed = raw.trim().toLowerCase(Locale.ROOT);
            WildcardPattern pattern = tryParseWildcardPattern(trimmed);
            if (pattern != null) {
                patterns.add(pattern);
            } else {
                String normalized = normalizeOrigin(trimmed);
                if (!normalized.isEmpty()) {
                    exact.add(normalized);
                }
            }
        }

        this.normalizedAllowedOrigins = Set.copyOf(exact);
        this.wildcardPatterns = List.copyOf(patterns);
    }

    /**
     * Validates an incoming HTTP {@code Origin} header value against the compiled Zero Trust whitelist.
     *
     * @param originHeader raw value of the HTTP {@code Origin} header during WebSocket upgrade
     * @return {@code true} if and only if the origin passes RFC 6454 canonical parsing and matches
     *         an authorized exact entry or bounded wildcard policy
     */
    public boolean isAllowed(String originHeader) {
        if (originHeader == null || originHeader.isBlank()) {
            return false;
        }
        if ("null".equalsIgnoreCase(originHeader.trim())) {
            // Reject sandboxed iframe / file:// 'null' origins per Zero Trust policy
            return false;
        }
        if (allowWildcardInDev) {
            return true;
        }

        ParsedOrigin parsed = parseOrigin(originHeader);
        if (parsed == null) {
            return false;
        }
        String canonical = formatCanonical(parsed);
        if (normalizedAllowedOrigins.contains(canonical)) {
            return true;
        }

        for (WildcardPattern pattern : wildcardPatterns) {
            if (!pattern.scheme().equals(parsed.scheme())) {
                continue;
            }
            if (pattern.anyPort()) {
                // Loopback arbitrary-port pattern (e.g. http://localhost:*, http://127.0.0.1:*)
                if (pattern.domainSuffix().equals(parsed.host())) {
                    return true;
                }
            } else if (parsed.effectivePort() == 443 && matchesSubdomain(parsed.host(), pattern.domainSuffix())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Canonicalizes an Origin string to 'scheme://host[:non-default-port]' in lowercase.
     * Prevents prefix bypasses such as 'https://chaska.ong.pe.attacker.com'.
     */
    static String normalizeOrigin(String rawOrigin) {
        ParsedOrigin parsed = parseOrigin(rawOrigin);
        return parsed != null ? formatCanonical(parsed) : "";
    }

    private static WildcardPattern tryParseWildcardPattern(String raw) {
        // 1. Subdomain wildcard strictly over HTTPS, e.g. https://*.pages.dev
        if (raw.startsWith("https://*.")) {
            String suffix = raw.substring("https://*.".length()).trim();
            if (!suffix.isEmpty()
                    && !suffix.contains("*")
                    && !suffix.contains("/")
                    && !suffix.contains(":")
                    && suffix.contains(".")) {
                return new WildcardPattern("https", suffix, false);
            }
            return null;
        }
        // 2. Any-port wildcard strictly for loopback hosts (localhost / 127.0.0.1)
        if (raw.endsWith(":*")) {
            String prefix = raw.substring(0, raw.length() - 2);
            ParsedOrigin parsed = parseOrigin(prefix);
            if (parsed != null && ("localhost".equals(parsed.host()) || "127.0.0.1".equals(parsed.host()))) {
                return new WildcardPattern(parsed.scheme(), parsed.host(), true);
            }
        }
        return null;
    }

    private static boolean matchesSubdomain(String host, String domainSuffix) {
        String dotSuffix = "." + domainSuffix;
        if (!host.endsWith(dotSuffix)) {
            return false;
        }
        String labelPrefix = host.substring(0, host.length() - dotSuffix.length());
        return !labelPrefix.isEmpty() && !labelPrefix.startsWith(".") && !labelPrefix.endsWith(".");
    }

    private static ParsedOrigin parseOrigin(String rawOrigin) {
        try {
            URI uri = URI.create(rawOrigin.trim());
            String scheme = uri.getScheme();
            String host = uri.getHost();
            int port = uri.getPort();

            if (scheme == null || host == null || host.isBlank()) {
                return null;
            }
            // Reject origins containing userinfo, paths (other than empty or '/'), query, or fragment
            if (uri.getUserInfo() != null || uri.getRawQuery() != null || uri.getRawFragment() != null) {
                return null;
            }
            String path = uri.getRawPath();
            if (path != null && !path.isEmpty() && !"/".equals(path)) {
                return null;
            }

            String lowerScheme = scheme.toLowerCase(Locale.ROOT);
            if (!"http".equals(lowerScheme) && !"https".equals(lowerScheme)) {
                return null;
            }

            int effectivePort = (port != -1) ? port : ("https".equals(lowerScheme) ? 443 : 80);
            return new ParsedOrigin(lowerScheme, host.toLowerCase(Locale.ROOT), effectivePort);
        } catch (Exception e) {
            return null;
        }
    }

    private static String formatCanonical(ParsedOrigin parsed) {
        boolean isDefaultPort = ("http".equals(parsed.scheme()) && parsed.effectivePort() == 80)
                || ("https".equals(parsed.scheme()) && parsed.effectivePort() == 443);
        return isDefaultPort
                ? parsed.scheme() + "://" + parsed.host()
                : parsed.scheme() + "://" + parsed.host() + ":" + parsed.effectivePort();
    }
}

