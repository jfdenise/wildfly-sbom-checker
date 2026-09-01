/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.sbom.scanner;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Scans the entire WildFly installation root for JAR files.
 *
 * <p>Every {@code *.jar} found anywhere under the installation root is
 * collected, except for files under {@code .installation/} (the Prospero
 * internal cache, not part of the runtime installation).</p>
 *
 * <p>No filename parsing is performed. The raw filename is stored as-is so
 * that callers can construct their own expected filename from authoritative
 * metadata (e.g. a CycloneDX SBOM component's {@code name} and
 * {@code version}) and compare directly, avoiding the ambiguity of splitting
 * artifact ids that themselves contain digit-prefixed segments (e.g.
 * {@code wildfly-clustering-session-spec-servlet-6.0-5.0.11.Final.jar}).</p>
 */
public class InstallationScanner {

    private final Path installRoot;

    /**
     * @param installRoot path to the WildFly installation root (the directory
     *                    that contains {@code jboss-modules.jar},
     *                    {@code modules/}, {@code bin/}, etc.).
     */
    public InstallationScanner(Path installRoot) {
        this.installRoot = installRoot;
    }

    /**
     * Walks the installation tree and returns every JAR found, except those
     * under {@code .installation/}.
     *
     * @return unmodifiable list of discovered artifacts
     * @throws IOException if the file tree cannot be walked
     */
    public List<InstalledArtifact> scan() throws IOException {
        List<InstalledArtifact> result = new ArrayList<>();
        Path excluded = installRoot.resolve(".installation").toAbsolutePath().normalize();

        Files.walkFileTree(installRoot, new SimpleFileVisitor<>() {

            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                if (dir.toAbsolutePath().normalize().startsWith(excluded)) {
                    return FileVisitResult.SKIP_SUBTREE;
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                if (file.getFileName().toString().endsWith(".jar")) {
                    result.add(new InstalledArtifact(
                            file.getFileName().toString(),
                            file.toAbsolutePath().toString()
                    ));
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFileFailed(Path file, IOException exc) {
                System.err.println("WARN: cannot read " + file + " – " + exc.getMessage());
                return FileVisitResult.CONTINUE;
            }
        });

        return Collections.unmodifiableList(result);
    }
}
