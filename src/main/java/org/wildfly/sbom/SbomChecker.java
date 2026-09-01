/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.sbom;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.component.evidence.Identity;
import org.cyclonedx.model.component.evidence.Method;
import org.cyclonedx.model.component.evidence.Occurrence;
import org.cyclonedx.parsers.JsonParser;
import org.wildfly.sbom.manifest.ManifestReader;
import org.wildfly.sbom.scanner.InstalledArtifact;
import org.wildfly.sbom.scanner.InstallationScanner;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Entry point for the WildFly SBOM checker.
 *
 * <p>Usage:
 * <pre>
 *   java -jar sbom-checker.jar &lt;install-root&gt;
 * </pre>
 *
 * <p>The tool performs three independent checks:
 * <ol>
 *   <li><b>SBOM ↔ disk</b>: every maven component listed in the SBOM must be
 *       verifiable on disk.</li>
 *   <li><b>Disk ↔ SBOM</b>: every JAR found on disk must be declared in the
 *       SBOM (no undeclared artifacts).</li>
 *   <li><b>SBOM ↔ manifest</b>: every maven component in the SBOM must appear
 *       in {@code .installation/manifest.yaml} with the same version.</li>
 * </ol>
 */
public class SbomChecker {

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("Usage: sbom-checker <install-root>");
            System.exit(1);
        }

        Path installRoot = Paths.get(args[0]).toAbsolutePath().normalize();
        if (!Files.isDirectory(installRoot)) {
            System.err.println("ERROR: not a directory: " + installRoot);
            System.exit(1);
        }

        System.out.println("Installation root : " + installRoot);

        // ---- 1. Parse the SBOM ----------------------------------------
        File sbomFile = installRoot.resolve("sbom.cdx.json").toFile();
        if (!sbomFile.exists()) {
            System.out.println("No sbom.cdx.json found in " + installRoot + " — skipping.");
            return;
        }

        long sbomSizeKb = sbomFile.length() / 1024;
        Bom bom = new JsonParser().parse(sbomFile);
        System.out.println("SBOM format       : " + bom.getBomFormat()
                + " " + bom.getSpecVersion()
                + "  (" + sbomSizeKb + " KB)");
        if (bom.getMetadata() != null && bom.getMetadata().getComponent() != null) {
            Component product = bom.getMetadata().getComponent();
            System.out.println("Product           : " + product.getName()
                    + " " + product.getVersion());
        }

        // Collect all maven components from the SBOM (flatten the two-level tree)
        List<Component> mavenComponents = collectMavenComponents(bom.getComponents());
        System.out.println("Maven components in SBOM : " + mavenComponents.size());

        // ---- 2. Scan the installation on disk --------------------------
        InstallationScanner scanner = new InstallationScanner(installRoot);
        List<InstalledArtifact> installedJars = scanner.scan();
        System.out.println("JARs found on disk       : " + installedJars.size());

        // ---- 3. Read manifest.yaml (optional) --------------------------
        Map<String, String> manifest = ManifestReader.read(installRoot);
        boolean hasManifest = !manifest.isEmpty();
        System.out.println("Manifest entries         : "
                + (hasManifest ? manifest.size() : "n/a (no manifest.yaml)"));

        System.out.println();
        printSbomBreakdown(bom.getComponents(), mavenComponents);

        // ---- Run checks ------------------------------------------------
        // Build shared indexes once
        Set<String> diskFileNames = installedJars.stream()
                .map(InstalledArtifact::jarFileName)
                .collect(Collectors.toSet());
        Map<String, String> parentIndex = buildParentIndex(bom.getComponents());

        CheckResult sbomVsDisk                  = checkSbomVsDisk(mavenComponents, installedJars, installRoot);
        CheckResult diskVsSbom                  = checkDiskVsSbom(installedJars, mavenComponents);
        Map<String, List<String>> shadedInfo    = collectShadedArtifacts(mavenComponents, diskFileNames, parentIndex);

        printResult("CHECK 1 — SBOM components present on disk", sbomVsDisk);
        printResult("CHECK 2 — Disk JARs declared in SBOM", diskVsSbom);
        if (hasManifest) {
            CheckResult sbomVsManifest = checkSbomVsManifest(mavenComponents, manifest);
            printResult("CHECK 3 — SBOM versions match manifest.yaml", sbomVsManifest);
        } else {
            printSkipped("CHECK 3 — SBOM versions match manifest.yaml",
                    "no .installation/manifest.yaml found in this installation");
        }
        printShadedInfo("INFO — SBOM artifacts not installed standalone (shaded/POM-derived)", shadedInfo);

        boolean allOk = sbomVsDisk.passed() && diskVsSbom.passed();
        System.out.println();
        System.out.println(allOk ? "RESULT: ALL CHECKS PASSED" : "RESULT: SOME CHECKS FAILED");
        System.exit(allOk ? 0 : 1);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /**
     * Maven artifacts that are installed under a fixed, unversioned filename.
     * These are real maven coordinates but their installed file does not follow
     * the {@code <name>-<version>.jar} convention.
     * Key: SBOM component {@code name}; value: path relative to install root.
     */
    static final Map<String, String> FAT_JAR_NAMES = Map.of(
            "wildfly-launcher", "bin/launcher.jar",
            "jboss-modules",    "jboss-modules.jar"
    );

    /**
     * Filenames of assembled fat JARs in {@code bin/} that are represented in
     * the SBOM only as {@code pkg:generic} top-level entries (never as maven
     * components). They are excluded from maven-level checks but must be
     * recognised in check 2 so they are not reported as undeclared.
     */
    static final Set<String> GENERIC_FAT_JAR_FILENAMES = Set.of(
            "jboss-cli-client.jar",
            "jboss-client.jar",
            "wildfly-elytron-tool.jar",
            "launcher.jar"
    );

    /**
     * Recursively collects all maven-coordinate components from the SBOM
     * component tree.
     */
    static List<Component> collectMavenComponents(List<Component> components) {
        if (components == null) return Collections.emptyList();
        List<Component> result = new ArrayList<>();
        for (Component c : components) {
            if (c.getPurl() != null && c.getPurl().startsWith("pkg:maven/")) {
                result.add(c);
            }
            result.addAll(collectMavenComponents(c.getComponents()));
        }
        return result;
    }

    /**
     * Builds a map from each maven component's purl to the purl of its
     * nearest parent in the SBOM component tree (the component whose
     * {@code components} list directly contains it).
     *
     * <p>Top-level components (with no parent) are not present in the map.</p>
     */
    static Map<String, String> buildParentIndex(List<Component> components) {
        Map<String, String> index = new java.util.LinkedHashMap<>();
        buildParentIndexRecursive(components, null, index);
        return index;
    }

    private static void buildParentIndexRecursive(
            List<Component> components, String parentPurl, Map<String, String> index) {
        if (components == null) return;
        for (Component c : components) {
            String purl = c.getPurl();
            if (purl != null && parentPurl != null) {
                index.put(purl, parentPurl);
            }
            buildParentIndexRecursive(c.getComponents(), purl, index);
        }
    }

    /**
     * CHECK 1: every maven component in the SBOM must be verifiable on disk.
     *
     * <p>Three sub-cases based on {@link #componentKind(Component)}:</p>
     * <ul>
     *   <li><b>POM_DERIVED</b> – sub-artifacts declared in a parent POM that
     *       were never installed as standalone files (e.g. {@code jansi-linux64}).
     *       Skipped.</li>
     *   <li><b>NATIVE_LIB</b> – ships as a native {@code .so}/{@code .dll}
     *       inside a module {@code lib/} directory. The directory is verified
     *       to exist.</li>
     *   <li><b>REGULAR_JAR</b> – expected filename is built directly from the
     *       SBOM component's {@code name} and {@code version}:
     *       {@code <name>-<version>[‑classifier].jar}, with a fallback to
     *       {@code <name>.jar} for unversioned installs (e.g.
     *       {@code jboss-modules.jar}).</li>
     * </ul>
     */
    private static CheckResult checkSbomVsDisk(
            List<Component> sbomComponents,
            List<InstalledArtifact> installedJars,
            Path installRoot) {

        // Index disk by raw filename — no parsing, no ambiguity.
        Set<String> diskFileNames = installedJars.stream()
                .map(InstalledArtifact::jarFileName)
                .collect(Collectors.toSet());

        List<String> missing = new ArrayList<>();
        for (Component c : sbomComponents) {
            switch (componentKind(c)) {

                case POM_DERIVED -> { /* nothing to check */ }

                case NATIVE_LIB -> {
                    String libDir = nativeLibDir(c);
                    if (libDir != null && !Files.isDirectory(installRoot.resolve(libDir))) {
                        missing.add(c.getPurl() + "  [native lib dir missing: " + libDir + "]");
                    }
                }

                case REGULAR_JAR -> {
                    // Skip non-JAR typed artifacts (e.g. type=txt)
                    if (isNonJarType(c)) break;

                    // Fat JARs installed under a fixed, unversioned filename
                    String fatJar = FAT_JAR_NAMES.get(c.getName());
                    if (fatJar != null) {
                        // Verify the specific expected path exists on disk
                        if (!Files.exists(installRoot.resolve(fatJar))) {
                            missing.add(c.getPurl() + "  [expected: " + fatJar + "]");
                        }
                        break;
                    }

                    String expected = expectedJarFileName(c);
                    if (!diskFileNames.contains(expected)) {
                        missing.add(c.getPurl() + "  [expected: " + expected + "]");
                    }
                }
            }
        }
        return new CheckResult(missing);
    }

    /**
     * CHECK 2: every JAR found on disk must be declared in the SBOM.
     *
     * <p>The SBOM side is indexed as the set of all expected filenames
     * (constructed from SBOM {@code name}+{@code version}, same logic as
     * check 1) plus the unversioned fallback {@code name.jar}.  JARs that
     * appear only in the SBOM as POM-derived sub-artifacts are excluded from
     * the index because they have no corresponding file on disk.</p>
     */
    private static CheckResult checkDiskVsSbom(
            List<InstalledArtifact> installedJars,
            List<Component> sbomComponents) {

        // Build the set of all filenames the SBOM accounts for
        Set<String> sbomFileNames = new HashSet<>();
        for (Component c : sbomComponents) {
            if (componentKind(c) == ComponentKind.POM_DERIVED) continue;
            if (isNonJarType(c)) continue;
            // Fat JARs use a fixed installed filename — add its basename
            String fatJar = FAT_JAR_NAMES.get(c.getName());
            if (fatJar != null) {
                // basename of e.g. "bin/client/jboss-cli-client.jar" → "jboss-cli-client.jar"
                sbomFileNames.add(Path.of(fatJar).getFileName().toString());
            } else {
                sbomFileNames.add(expectedJarFileName(c));
            }
        }

        Set<String> reported = new HashSet<>();
        List<String> undeclared = new ArrayList<>();
        for (InstalledArtifact jar : installedJars) {
            String name = jar.jarFileName();
            if (!sbomFileNames.contains(name)
                    && !GENERIC_FAT_JAR_FILENAMES.contains(name)
                    && reported.add(name)) {
                undeclared.add(name);
            }
        }
        return new CheckResult(undeclared);
    }

    /**
     * CHECK 3: every maven component in the SBOM must be present in
     * manifest.yaml and the versions must match.
     */
    private static CheckResult checkSbomVsManifest(
            List<Component> sbomComponents,
            Map<String, String> manifest) {

        List<String> issues = new ArrayList<>();
        for (Component c : sbomComponents) {
            // Skip shaded/POM-derived sub-artifacts — they are bundled inside
            // another JAR and are not independently tracked by the manifest.
            if (componentKind(c) == ComponentKind.POM_DERIVED) continue;

            String coord = c.getGroup() + ":" + c.getName();
            String manifestVersion = manifest.get(coord);
            if (manifestVersion == null) {
                issues.add("NOT IN MANIFEST  " + coord + "  (sbom: " + c.getVersion() + ")");
            } else if (!manifestVersion.equals(c.getVersion())) {
                issues.add("VERSION MISMATCH " + coord
                        + "  sbom=" + c.getVersion()
                        + "  manifest=" + manifestVersion);
            }
        }
        return new CheckResult(issues);
    }

    // -----------------------------------------------------------------------
    // Component classification
    // -----------------------------------------------------------------------

    enum ComponentKind { POM_DERIVED, NATIVE_LIB, REGULAR_JAR }

    /**
     * Classifies a component for check 1.
     *
     * <ul>
     *   <li>{@code POM_DERIVED} – only {@code manifest-analysis /
     *       maven-pom-analysis} evidence and no occurrences; these are
     *       sub-artifacts declared in a parent POM that were never installed
     *       as standalone files (e.g. platform-specific jansi sub-jars).</li>
     *   <li>{@code NATIVE_LIB} – at least one occurrence whose location ends
     *       with {@code /lib}; the component ships as a native
     *       {@code .so}/{@code .dll} inside a module lib directory.</li>
     *   <li>{@code REGULAR_JAR} – everything else.</li>
     * </ul>
     */
    static ComponentKind componentKind(Component c) {
        Evidence ev = c.getEvidence();
        if (ev == null) return ComponentKind.REGULAR_JAR;

        List<Occurrence> occurrences = ev.getOccurrences();
        if (occurrences != null && !occurrences.isEmpty()) {
            boolean allLib = occurrences.stream()
                    .allMatch(o -> o.getLocation() != null && o.getLocation().endsWith("/lib"));
            return allLib ? ComponentKind.NATIVE_LIB : ComponentKind.REGULAR_JAR;
        }

        List<Identity> identities = ev.getIdentities();
        if (identities != null && !identities.isEmpty()) {
            boolean allPomDerived = identities.stream().allMatch(id -> {
                List<Method> methods = id.getMethods();
                if (methods == null || methods.isEmpty()) return false;
                return methods.stream().allMatch(m ->
                        m.getTechnique() == Method.Technique.MANIFEST_ANALYSIS
                        && "maven-pom-analysis".equals(m.getValue()));
            });
            if (allPomDerived) return ComponentKind.POM_DERIVED;
        }

        return ComponentKind.REGULAR_JAR;
    }

    /**
     * Returns the relative path of the native lib directory from the first
     * matching occurrence, or {@code null} if none is found.
     */
    static String nativeLibDir(Component c) {
        Evidence ev = c.getEvidence();
        if (ev == null || ev.getOccurrences() == null) return null;
        return ev.getOccurrences().stream()
                .map(Occurrence::getLocation)
                .filter(loc -> loc != null && loc.endsWith("/lib"))
                .findFirst()
                .orElse(null);
    }

    // -----------------------------------------------------------------------
    // Filename helpers — derive expected names from SBOM metadata
    // -----------------------------------------------------------------------

    /**
     * Builds the expected on-disk JAR filename from a component's SBOM
     * metadata: {@code <name>-<version>[‑classifier].jar}.
     *
     * <p>For classifier purls such as
     * {@code pkg:maven/io.netty/netty-transport-native-unix-common@4.1.116.Final?classifier=linux-x86_64}
     * the classifier is appended with a hyphen, matching the Maven install
     * convention:
     * {@code netty-transport-native-unix-common-4.1.116.Final-linux-x86_64.jar}.</p>
     */
    static String expectedJarFileName(Component c) {
        String classifier = purlClassifier(c.getPurl());
        String versionSuffix = (classifier != null && !classifier.isBlank())
                ? c.getVersion() + "-" + classifier
                : c.getVersion();
        return c.getName() + "-" + versionSuffix + ".jar";
    }

    /**
     * Returns {@code true} when the purl declares a {@code type} qualifier
     * that is not {@code jar} (e.g. {@code type=txt}).  Such entries are not
     * JAR files and should not be looked up on disk.
     */
    static boolean isNonJarType(Component c) {
        String purl = c.getPurl();
        if (purl == null) return false;
        int q = purl.indexOf('?');
        if (q < 0) return false;
        for (String param : purl.substring(q + 1).split("&")) {
            if (param.startsWith("type=") && !param.equals("type=jar")) {
                return true;
            }
        }
        return false;
    }

    /**
     * Extracts the {@code classifier} query parameter from a purl, or
     * {@code null} if absent.
     */
    static String purlClassifier(String purl) {
        if (purl == null) return null;
        int q = purl.indexOf('?');
        if (q < 0) return null;
        for (String param : purl.substring(q + 1).split("&")) {
            if (param.startsWith("classifier=")) {
                return param.substring("classifier=".length());
            }
        }
        return null;
    }

    /**
     * Collects POM-derived components that have no corresponding standalone
     * JAR on disk — i.e. they are either shaded into another JAR or are
     * optional/test-scoped dependencies that were never installed.
     *
     * <p>Components whose expected filename ({@code name-version.jar}) does
     * exist on disk are excluded: they are real installed JARs that happen to
     * also appear as a POM dependency of another component.</p>
     */
    /**
     * Groups shaded/POM-derived artifacts by their parent purl.
     * Key: parent purl (or "(no parent)" for orphans); value: sorted list of child purls.
     */
    private static Map<String, List<String>> collectShadedArtifacts(
            List<Component> allMavenComponents,
            Set<String> diskFileNames,
            Map<String, String> parentIndex) {
        // LinkedHashMap preserves insertion order; we'll sort keys before printing
        Map<String, List<String>> grouped = new java.util.TreeMap<>();
        allMavenComponents.stream()
                .filter(c -> componentKind(c) == ComponentKind.POM_DERIVED)
                .filter(c -> !diskFileNames.contains(expectedJarFileName(c)))
                // Also exclude fat JARs that are installed under a fixed unversioned name
                .filter(c -> {
                    String fatJar = FAT_JAR_NAMES.get(c.getName());
                    if (fatJar == null) return true;
                    return !diskFileNames.contains(Path.of(fatJar).getFileName().toString());
                })
                .forEach(c -> {
                    String parent = parentIndex.getOrDefault(c.getPurl(), "(no parent)");
                    grouped.computeIfAbsent(parent, k -> new ArrayList<>()).add(c.getPurl());
                });
        grouped.values().forEach(Collections::sort);
        return grouped;
    }

    /**
     * Prints a breakdown of all SBOM entries by kind, explaining the gap
     * between the total component count and the number of JARs on disk.
     *
     * <p>Categories:
     * <ul>
     *   <li><b>pkg:generic fat-JAR wrappers</b> – top-level {@code pkg:generic}
     *       envelope entries that represent assembled fat JARs; they carry no
     *       direct file on disk themselves.</li>
     *   <li><b>Native .so/.dll</b> – components whose occurrence location ends
     *       with {@code /lib}; installed as shared libraries, not JARs.</li>
     *   <li><b>POM-derived / shaded</b> – {@code maven-pom-analysis} only,
     *       no occurrences; bundled inside a parent JAR.</li>
     *   <li><b>Non-JAR type</b> – purl carries {@code type=} qualifier that is
     *       not {@code jar} (e.g. {@code type=txt}).</li>
     *   <li><b>Installable JARs</b> – everything else; each maps to exactly one
     *       JAR on disk.</li>
     * </ul>
     */
    private static void printSbomBreakdown(List<Component> topLevel, List<Component> allMaven) {
        // Collect pkg:generic top-level wrappers (not in allMaven, which filters for pkg:maven only)
        List<String> genericTopNames = topLevel == null ? Collections.emptyList() : topLevel.stream()
                .filter(c -> c.getPurl() != null && c.getPurl().startsWith("pkg:generic/"))
                .map(Component::getName)
                .sorted()
                .collect(Collectors.toList());

        long nativeLib   = 0;
        long pomDerived  = 0;
        long nonJarType  = 0;
        long installable = 0;

        for (Component c : allMaven) {
            ComponentKind k = componentKind(c);
            if (k == ComponentKind.NATIVE_LIB) {
                nativeLib++;
            } else if (k == ComponentKind.POM_DERIVED) {
                pomDerived++;
            } else if (isNonJarType(c)) {
                nonJarType++;
            } else {
                installable++;
            }
        }

        long total = genericTopNames.size() + allMaven.size();

        System.out.println("┌─ SBOM entry breakdown");
        System.out.printf("│  Total entries                          : %4d%n", total);
        System.out.printf("│    Bundled fat JARs (no version on disk): %4d  (%s)%n",
                genericTopNames.size(), String.join(", ", genericTopNames));
        System.out.printf("│    Native .so/.dll                      : %4d  (installed as shared libraries under lib/)%n", nativeLib);
        System.out.printf("│    POM-derived / shaded                 : %4d  (bundled inside a parent JAR)%n", pomDerived);
        System.out.printf("│    Non-JAR type                         : %4d  (type=txt or similar, not a JAR)%n", nonJarType);
        System.out.printf("│    Installable JARs                     : %4d  (expected on disk)%n", installable);
        System.out.println();
    }

    private static void printShadedInfo(String title, Map<String, List<String>> grouped) {
        System.out.println("┌─ " + title);
        if (grouped.isEmpty()) {
            System.out.println("│  (none)");
        } else {
            int total = grouped.values().stream().mapToInt(List::size).sum();
            System.out.println("│  " + total + " artifact(s) in " + grouped.size() + " group(s):");
            grouped.forEach((parent, children) -> {
                System.out.println("│");
                System.out.println("│  ┌ " + parent);
                for (String child : children) {
                    System.out.println("│  │   ℹ " + child);
                }
            });
        }
        System.out.println();
    }

    // -----------------------------------------------------------------------

    private static void printSkipped(String title, String reason) {
        System.out.println("┌─ " + title);
        System.out.println("│  SKIPPED – " + reason);
        System.out.println();
    }

    private static void printResult(String title, CheckResult result) {
        System.out.println("┌─ " + title);
        if (result.passed()) {
            System.out.println("│  OK – no issues found");
        } else {
            System.out.println("│  FAILED – " + result.issues().size() + " issue(s):");
            for (String issue : result.issues()) {
                System.out.println("│    • " + issue);
            }
        }
        System.out.println();
    }

    record CheckResult(List<String> issues) {
        boolean passed() { return issues.isEmpty(); }
    }
}
