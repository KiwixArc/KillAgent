package pe.ong.chasca.killagent.update;

import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Strict Semantic Versioning 2.0.0 comparator supporting stable, pre-release,
 * and SNAPSHOT version strings (with optional leading 'v' prefix).
 */
public record SemanticVersion(int major, int minor, int patch, String preRelease)
        implements Comparable<SemanticVersion> {

    private static final Pattern SEMVER_PATTERN = Pattern.compile(
            "^[vV]?(\\d+)(?:\\.(\\d+))?(?:\\.(\\d+))?(?:-([0-9A-Za-z.-]+))?(?:\\+.*)?$"
    );

    public SemanticVersion {
        if (major < 0 || minor < 0 || patch < 0) {
            throw new IllegalArgumentException("Version components cannot be negative.");
        }
        preRelease = preRelease != null ? preRelease.trim() : "";
    }

    public static SemanticVersion parse(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new IllegalArgumentException("Version string cannot be empty.");
        }
        Matcher matcher = SEMVER_PATTERN.matcher(raw.trim());
        if (!matcher.matches()) {
            throw new IllegalArgumentException("Invalid semantic version format: '" + raw + "'");
        }
        int major = Integer.parseInt(matcher.group(1));
        int minor = matcher.group(2) != null ? Integer.parseInt(matcher.group(2)) : 0;
        int patch = matcher.group(3) != null ? Integer.parseInt(matcher.group(3)) : 0;
        String preRelease = matcher.group(4) != null ? matcher.group(4) : "";
        return new SemanticVersion(major, minor, patch, preRelease);
    }

    public boolean isNewerThan(SemanticVersion other) {
        Objects.requireNonNull(other, "other version must not be null");
        return compareTo(other) > 0;
    }

    public boolean isPreRelease() {
        return !preRelease.isEmpty();
    }

    @Override
    public int compareTo(SemanticVersion other) {
        int c = Integer.compare(this.major, other.major);
        if (c != 0) return c;
        c = Integer.compare(this.minor, other.minor);
        if (c != 0) return c;
        c = Integer.compare(this.patch, other.patch);
        if (c != 0) return c;

        boolean thisPre = this.isPreRelease();
        boolean otherPre = other.isPreRelease();
        if (!thisPre && !otherPre) return 0;
        if (!thisPre) return 1;  // Stable release is newer than pre-release of same tuple
        if (!otherPre) return -1;

        return comparePreRelease(this.preRelease, other.preRelease);
    }

    private static int comparePreRelease(String left, String right) {
        String[] leftParts = left.split("\\.");
        String[] rightParts = right.split("\\.");
        int len = Math.max(leftParts.length, rightParts.length);

        for (int i = 0; i < len; i++) {
            if (i >= leftParts.length) return -1;
            if (i >= rightParts.length) return 1;

            String a = leftParts[i];
            String b = rightParts[i];
            boolean aNum = isDigitsOnly(a);
            boolean bNum = isDigitsOnly(b);

            if (aNum && bNum) {
                int cmp = Long.compare(Long.parseLong(a), Long.parseLong(b));
                if (cmp != 0) return cmp;
            } else if (aNum) {
                return -1; // Numeric identifiers always have lower precedence than non-numeric
            } else if (bNum) {
                return 1;
            } else {
                int cmp = a.compareTo(b);
                if (cmp != 0) return cmp;
            }
        }
        return 0;
    }

    private static boolean isDigitsOnly(String value) {
        if (value == null || value.isEmpty()) return false;
        for (int i = 0; i < value.length(); i++) {
            if (!Character.isDigit(value.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    @Override
    public String toString() {
        String core = major + "." + minor + "." + patch;
        return preRelease.isEmpty() ? core : core + "-" + preRelease;
    }
}
