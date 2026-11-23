import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

/**
 * Standalone JDK 21 CLI utility for Ed25519 manifest key generation, signing, and verification.
 * Requires zero external dependencies so release pipelines can sign manifests immediately.
 *
 * Usage:
 *   java scripts/ManifestSigner.java keygen
 *   java scripts/ManifestSigner.java sign   <manifest.json> <base64-pkcs8-private-key>
 *   java scripts/ManifestSigner.java verify <manifest.json> <base64-spki-public-key>
 */
public final class ManifestSigner {

    private ManifestSigner() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            printUsageAndExit();
        }
        String cmd = args[0].trim().toLowerCase(Locale.ROOT);
        switch (cmd) {
            case "keygen" -> handleKeygen();
            case "canonical" -> {
                requireArgs(args, 2);
                Map<String, Object> root = asObject(new JsonParser(Files.readString(Paths.get(args[1]), StandardCharsets.UTF_8)).parse());
                System.out.print(buildCanonicalPayload(root));
            }
            case "sign" -> {
                requireArgs(args, 3);
                handleSign(Paths.get(args[1]), args[2].trim());
            }
            case "verify" -> {
                requireArgs(args, 3);
                handleVerify(Paths.get(args[1]), args[2].trim());
            }
            default -> printUsageAndExit();
        }
    }

    private static void handleKeygen() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
        KeyPair kp = kpg.generateKeyPair();
        String privB64 = Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded());
        String pubB64 = Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());
        System.out.println("UPDATE_SIGNING_PRIVATE_KEY=" + privB64);
        System.out.println("UPDATE_SIGNING_PUBLIC_KEY=" + pubB64);
    }

    private static void handleSign(Path manifestPath, String privateKeyB64) throws Exception {
        String rawJson = Files.readString(manifestPath, StandardCharsets.UTF_8);
        Map<String, Object> root = asObject(new JsonParser(rawJson).parse());
        String payload = buildCanonicalPayload(root);

        byte[] privBytes = Base64.getDecoder().decode(privateKeyB64);
        PrivateKey privKey = KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(privBytes));
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(privKey);
        signer.update(payload.getBytes(StandardCharsets.UTF_8));
        String signatureB64 = Base64.getEncoder().encodeToString(signer.sign());

        root.put("signature", signatureB64);
        Files.writeString(manifestPath, toPrettyJson(root, 0) + System.lineSeparator(), StandardCharsets.UTF_8);
        System.out.println("Signed update manifest with Ed25519: " + manifestPath);
    }

    private static void handleVerify(Path manifestPath, String publicKeyB64) throws Exception {
        String rawJson = Files.readString(manifestPath, StandardCharsets.UTF_8);
        Map<String, Object> root = asObject(new JsonParser(rawJson).parse());
        String signatureB64 = asString(root.get("signature")).trim();
        if (signatureB64.isEmpty()) {
            System.err.println("Manifest signature field is empty.");
            System.exit(1);
        }

        String payload = buildCanonicalPayload(root);
        byte[] pubBytes = Base64.getDecoder().decode(publicKeyB64);
        byte[] sigBytes = Base64.getDecoder().decode(signatureB64);
        PublicKey pubKey = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(pubBytes));
        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(pubKey);
        verifier.update(payload.getBytes(StandardCharsets.UTF_8));

        if (!verifier.verify(sigBytes)) {
            System.err.println("Ed25519 manifest signature verification FAILED.");
            System.exit(1);
        }
        System.out.println("Ed25519 manifest signature VERIFIED successfully.");
    }

    private static String buildCanonicalPayload(Map<String, Object> root) {
        StringBuilder sb = new StringBuilder(256);
        sb.append("schemaVersion=").append(asLong(root.get("schemaVersion"))).append('\n');
        sb.append("product=").append(asString(root.get("product")).trim()).append('\n');
        sb.append("channel=").append(asString(root.get("channel")).trim()).append('\n');
        sb.append("version=").append(asString(root.get("version")).trim()).append('\n');
        sb.append("mandatory=").append(asBoolean(root.get("mandatory"))).append('\n');
        sb.append("minimumSupportedVersion=").append(asString(root.get("minimumSupportedVersion")).trim()).append('\n');

        TreeMap<String, Map<String, Object>> sorted = new TreeMap<>();
        Object rawArtifacts = root.get("artifacts");
        if (rawArtifacts instanceof Map<?, ?> map) {
            for (Map.Entry<?, ?> e : map.entrySet()) {
                if (e.getKey() != null && e.getValue() instanceof Map<?, ?>) {
                    sorted.put(e.getKey().toString(), asObject(e.getValue()));
                }
            }
        }
        for (Map.Entry<String, Map<String, Object>> entry : sorted.entrySet()) {
            Map<String, Object> info = entry.getValue();
            sb.append("artifact.").append(entry.getKey()).append('=')
                    .append(asString(info.get("fileName")).trim()).append('|')
                    .append(asString(info.get("url")).trim()).append('|')
                    .append(asString(info.get("sha256")).trim().toLowerCase(Locale.ROOT)).append('|')
                    .append(asLong(info.get("sizeBytes"))).append('\n');
        }
        return sb.toString();
    }

    private static void requireArgs(String[] args, int count) {
        if (args.length < count) {
            printUsageAndExit();
        }
    }

    private static void printUsageAndExit() {
        System.err.println("Usage:");
        System.err.println("  java scripts/ManifestSigner.java keygen");
        System.err.println("  java scripts/ManifestSigner.java sign <manifest.json> <privateKeyBase64>");
        System.err.println("  java scripts/ManifestSigner.java verify <manifest.json> <publicKeyBase64>");
        System.exit(2);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asObject(Object o) {
        if (o instanceof Map<?, ?> m) {
            return (Map<String, Object>) m;
        }
        throw new IllegalArgumentException("Expected JSON object");
    }

    private static String asString(Object o) {
        return o == null ? "" : String.valueOf(o);
    }

    private static boolean asBoolean(Object o) {
        return o instanceof Boolean b ? b : Boolean.parseBoolean(asString(o));
    }

    private static long asLong(Object o) {
        if (o instanceof Number n) return n.longValue();
        String s = asString(o).trim();
        return s.isEmpty() ? 0L : Long.parseLong(s);
    }

    private static String toPrettyJson(Object value, int indent) {
        String pad = "  ".repeat(indent);
        String childPad = "  ".repeat(indent + 1);
        if (value == null) return "null";
        if (value instanceof Boolean || value instanceof Number) return value.toString();
        if (value instanceof String s) return "\"" + escapeJson(s) + "\"";
        if (value instanceof Map<?, ?> map) {
            if (map.isEmpty()) return "{}";
            StringBuilder sb = new StringBuilder("{\n");
            int i = 0;
            int size = map.size();
            for (Map.Entry<?, ?> e : map.entrySet()) {
                sb.append(childPad)
                        .append("\"").append(escapeJson(String.valueOf(e.getKey()))).append("\": ")
                        .append(toPrettyJson(e.getValue(), indent + 1));
                if (++i < size) sb.append(',');
                sb.append('\n');
            }
            sb.append(pad).append('}');
            return sb.toString();
        }
        throw new IllegalArgumentException("Unsupported JSON value type: " + value.getClass());
    }

    private static String escapeJson(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
    }

    private static final class JsonParser {
        private final String src;
        private int pos;

        JsonParser(String src) {
            this.src = src;
        }

        Object parse() {
            skipWhitespace();
            Object v = parseValue();
            skipWhitespace();
            return v;
        }

        private Object parseValue() {
            skipWhitespace();
            if (pos >= src.length()) throw new IllegalArgumentException("Unexpected end of JSON");
            char c = src.charAt(pos);
            return switch (c) {
                case '{' -> parseObject();
                case '"' -> parseString();
                case 't', 'f' -> parseBoolean();
                case 'n' -> parseNull();
                default -> parseNumber();
            };
        }

        private Map<String, Object> parseObject() {
            expect('{');
            Map<String, Object> map = new LinkedHashMap<>();
            skipWhitespace();
            if (peek('}')) {
                pos++;
                return map;
            }
            while (true) {
                skipWhitespace();
                String key = parseString();
                skipWhitespace();
                expect(':');
                Object val = parseValue();
                map.put(key, val);
                skipWhitespace();
                if (peek('}')) {
                    pos++;
                    break;
                }
                expect(',');
            }
            return map;
        }

        private String parseString() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (pos < src.length()) {
                char c = src.charAt(pos++);
                if (c == '"') return sb.toString();
                if (c == '\\') {
                    char esc = src.charAt(pos++);
                    switch (esc) {
                        case '"', '\\', '/' -> sb.append(esc);
                        case 'b' -> sb.append('\b');
                        case 'f' -> sb.append('\f');
                        case 'n' -> sb.append('\n');
                        case 'r' -> sb.append('\r');
                        case 't' -> sb.append('\t');
                        case 'u' -> {
                            String hex = src.substring(pos, pos + 4);
                            pos += 4;
                            sb.append((char) Integer.parseInt(hex, 16));
                        }
                        default -> throw new IllegalArgumentException("Invalid escape: \\" + esc);
                    }
                } else {
                    sb.append(c);
                }
            }
            throw new IllegalArgumentException("Unterminated string literal");
        }

        private Boolean parseBoolean() {
            if (src.startsWith("true", pos)) {
                pos += 4;
                return Boolean.TRUE;
            }
            if (src.startsWith("false", pos)) {
                pos += 5;
                return Boolean.FALSE;
            }
            throw new IllegalArgumentException("Invalid boolean at pos " + pos);
        }

        private Object parseNull() {
            if (src.startsWith("null", pos)) {
                pos += 4;
                return null;
            }
            throw new IllegalArgumentException("Invalid null at pos " + pos);
        }

        private Number parseNumber() {
            int start = pos;
            if (src.charAt(pos) == '-') pos++;
            while (pos < src.length() && Character.isDigit(src.charAt(pos))) pos++;
            String num = src.substring(start, pos);
            return Long.parseLong(num);
        }

        private void skipWhitespace() {
            while (pos < src.length() && Character.isWhitespace(src.charAt(pos))) pos++;
        }

        private boolean peek(char c) {
            return pos < src.length() && src.charAt(pos) == c;
        }

        private void expect(char expected) {
            if (pos >= src.length() || src.charAt(pos) != expected) {
                throw new IllegalArgumentException("Expected '" + expected + "' at pos " + pos);
            }
            pos++;
        }
    }
}
