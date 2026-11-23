package pe.ong.chasca.killagent.update;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SemanticVersionTest {

    @Test
    void testParsesWithAndWithoutLeadingVAndBuildMetadata() {
        SemanticVersion v1 = SemanticVersion.parse("v1.2.3");
        SemanticVersion v2 = SemanticVersion.parse("1.2.3+build.42");
        assertEquals(v1, v2);
        assertEquals("1.2.3", v1.toString());

        SemanticVersion partial = SemanticVersion.parse("2.1");
        assertEquals(new SemanticVersion(2, 1, 0, ""), partial);
    }

    @Test
    void testStrictSemVerOrderingIncludingPreRelease() {
        assertTrue(SemanticVersion.parse("1.0.1").isNewerThan(SemanticVersion.parse("1.0.0")));
        assertTrue(SemanticVersion.parse("1.1.0").isNewerThan(SemanticVersion.parse("1.0.9")));
        assertTrue(SemanticVersion.parse("2.0.0").isNewerThan(SemanticVersion.parse("1.9.9")));

        // Stable release > pre-release of identical major.minor.patch
        assertTrue(SemanticVersion.parse("1.0.0").isNewerThan(SemanticVersion.parse("1.0.0-SNAPSHOT")));
        assertTrue(SemanticVersion.parse("1.0.0").isNewerThan(SemanticVersion.parse("1.0.0-beta.2")));
        assertTrue(SemanticVersion.parse("1.0.0-beta.10").isNewerThan(SemanticVersion.parse("1.0.0-beta.2")));

        assertFalse(SemanticVersion.parse("1.0.0").isNewerThan(SemanticVersion.parse("1.0.0")));
    }

    @Test
    void testInvalidVersionsThrow() {
        assertThrows(IllegalArgumentException.class, () -> SemanticVersion.parse(""));
        assertThrows(IllegalArgumentException.class, () -> SemanticVersion.parse("not-a-version"));
    }
}
