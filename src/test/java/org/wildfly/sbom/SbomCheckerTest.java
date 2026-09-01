/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.sbom;

import org.cyclonedx.model.Component;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.component.evidence.Identity;
import org.cyclonedx.model.component.evidence.Method;
import org.cyclonedx.model.component.evidence.Occurrence;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SbomCheckerTest {

    private static Component mavenComponent(String group, String name, String version) {
        Component c = new Component();
        c.setGroup(group);
        c.setName(name);
        c.setVersion(version);
        c.setPurl("pkg:maven/" + group + "/" + name + "@" + version);
        return c;
    }

    private static Component mavenComponentWithClassifier(
            String group, String name, String version, String classifier) {
        Component c = new Component();
        c.setGroup(group);
        c.setName(name);
        c.setVersion(version);
        c.setPurl("pkg:maven/" + group + "/" + name + "@" + version + "?classifier=" + classifier);
        return c;
    }

    private static Component mavenComponentWithType(
            String group, String name, String version, String type) {
        Component c = new Component();
        c.setGroup(group);
        c.setName(name);
        c.setVersion(version);
        c.setPurl("pkg:maven/" + group + "/" + name + "@" + version + "?type=" + type);
        return c;
    }

    // ---- collectMavenComponents -------------------------------------------

    @Test
    void collectMavenComponents_skipsGenericTopLevel() {
        Component generic = new Component();
        generic.setPurl("pkg:generic/jboss-cli-client@8.1");
        generic.setName("jboss-cli-client");
        generic.setVersion("8.1");

        Component child = mavenComponent("org.jboss", "jboss-dmr", "1.7.0.Final");
        generic.setComponents(List.of(child));

        List<Component> result = SbomChecker.collectMavenComponents(List.of(generic));

        assertEquals(1, result.size());
        assertEquals("jboss-dmr", result.get(0).getName());
    }

    @Test
    void collectMavenComponents_includesFlatMavenEntries() {
        Component c = mavenComponent("org.jboss", "jboss-dmr", "1.7.0.Final");
        assertEquals(1, SbomChecker.collectMavenComponents(List.of(c)).size());
    }

    @Test
    void collectMavenComponents_nullListReturnsEmpty() {
        assertTrue(SbomChecker.collectMavenComponents(null).isEmpty());
    }

    // ---- expectedJarFileName ----------------------------------------------

    @Test
    void expectedJarFileName_simple() {
        Component c = mavenComponent("org.jboss.logging", "jboss-logging", "3.6.1.Final");
        assertEquals("jboss-logging-3.6.1.Final.jar", SbomChecker.expectedJarFileName(c));
    }

    @Test
    void expectedJarFileName_withClassifier() {
        Component c = mavenComponentWithClassifier(
                "io.netty", "netty-transport-native-unix-common", "4.1.116.Final", "linux-x86_64");
        assertEquals("netty-transport-native-unix-common-4.1.116.Final-linux-x86_64.jar",
                SbomChecker.expectedJarFileName(c));
    }

    @Test
    void expectedJarFileName_artifactIdWithDigitSegment() {
        // The critical case: artifact id itself contains a digit segment
        Component c = mavenComponent(
                "org.wildfly.clustering",
                "wildfly-clustering-session-spec-servlet-6.0",
                "5.0.11.Final");
        assertEquals("wildfly-clustering-session-spec-servlet-6.0-5.0.11.Final.jar",
                SbomChecker.expectedJarFileName(c));
    }

    // ---- isNonJarType -----------------------------------------------------

    @Test
    void isNonJarType_txtIsTrue() {
        Component c = mavenComponentWithType(
                "org.wildfly", "wildfly-ee-feature-pack-product-conf",
                "8.1.1.GA-SNAPSHOT", "txt");
        assertTrue(SbomChecker.isNonJarType(c));
    }

    @Test
    void isNonJarType_noTypeIsFalse() {
        Component c = mavenComponent("org.foo", "foo", "1.0");
        assertFalse(SbomChecker.isNonJarType(c));
    }

    @Test
    void isNonJarType_explicitJarIsFalse() {
        Component c = mavenComponentWithType("org.foo", "foo", "1.0", "jar");
        assertFalse(SbomChecker.isNonJarType(c));
    }

    // ---- componentKind ----------------------------------------------------

    @Test
    void componentKind_noEvidence_isRegularJar() {
        assertEquals(SbomChecker.ComponentKind.REGULAR_JAR,
                SbomChecker.componentKind(mavenComponent("org.foo", "foo", "1.0")));
    }

    @Test
    void componentKind_pomDerived() {
        Component c = new Component();
        c.setName("jansi-linux64");
        c.setVersion("1.8");

        Evidence ev = new Evidence();
        Identity id = new Identity();
        Method m = new Method();
        m.setTechnique(Method.Technique.MANIFEST_ANALYSIS);
        m.setValue("maven-pom-analysis");
        id.setMethods(List.of(m));
        ev.setIdentities(List.of(id));
        c.setEvidence(ev);

        assertEquals(SbomChecker.ComponentKind.POM_DERIVED, SbomChecker.componentKind(c));
    }

    @Test
    void componentKind_nativeLib() {
        Component c = new Component();
        c.setName("wildfly-openssl-linux-ppc64le");
        c.setVersion("2.2.2.Final-redhat-00002");

        Occurrence occ = new Occurrence();
        occ.setLocation("modules/system/layers/base/org/wildfly/openssl/main/lib");
        Evidence ev = new Evidence();
        ev.setOccurrences(List.of(occ));
        c.setEvidence(ev);

        assertEquals(SbomChecker.ComponentKind.NATIVE_LIB, SbomChecker.componentKind(c));
    }

    @Test
    void componentKind_pomDerived_skippedInManifestCheck() {
        // A shaded sub-dependency (e.g. gson-2.10.1 inside nimbus-jose-jwt)
        // must be classified POM_DERIVED so check 3 skips it.
        Component c = new Component();
        c.setName("gson");
        c.setVersion("2.10.1");
        c.setGroup("com.google.code.gson");
        c.setPurl("pkg:maven/com.google.code.gson/gson@2.10.1");

        Evidence ev = new Evidence();
        Identity id = new Identity();
        Method m = new Method();
        m.setTechnique(Method.Technique.MANIFEST_ANALYSIS);
        m.setValue("maven-pom-analysis");
        id.setMethods(List.of(m));
        ev.setIdentities(List.of(id));
        c.setEvidence(ev);

        assertEquals(SbomChecker.ComponentKind.POM_DERIVED, SbomChecker.componentKind(c));
    }

    @Test
    void componentKind_occurrenceNotLib_isRegularJar() {
        Component c = new Component();
        c.setName("wildfly-openssl-java");
        c.setVersion("2.2.5.Final");

        Occurrence occ = new Occurrence();
        occ.setLocation("modules/system/layers/base/org/wildfly/openssl/main/wildfly-openssl-java-2.2.5.Final.jar");
        Evidence ev = new Evidence();
        ev.setOccurrences(List.of(occ));
        c.setEvidence(ev);

        assertEquals(SbomChecker.ComponentKind.REGULAR_JAR, SbomChecker.componentKind(c));
    }
}
