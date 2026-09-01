/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.sbom.manifest;

import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Reads the Prospero {@code .installation/manifest.yaml} file and returns a
 * map of {@code groupId:artifactId} → version for every stream entry.
 *
 * <p>The manifest uses the schema:</p>
 * <pre>
 * schemaVersion: "1.1.0"
 * streams:
 *   - groupId: "com.fasterxml.jackson.core"
 *     artifactId: "jackson-databind"
 *     version: "2.18.2"
 * </pre>
 */
public class ManifestReader {

    private ManifestReader() {}

    /**
     * Parses the manifest and returns an unmodifiable map where the key is
     * {@code groupId:artifactId} and the value is the version string.
     *
     * @param installRoot path to the WildFly installation root
     * @return map of coordinates to version; empty if the file is absent
     * @throws IOException on I/O errors
     */
    @SuppressWarnings("unchecked")
    public static Map<String, String> read(Path installRoot) throws IOException {
        Path manifestPath = installRoot.resolve(".installation").resolve("manifest.yaml");
        if (!Files.exists(manifestPath)) {
            return Collections.emptyMap();
        }

        Yaml yaml = new Yaml();
        try (InputStream is = Files.newInputStream(manifestPath)) {
            Map<String, Object> root = yaml.load(is);
            List<Map<String, String>> streams =
                    (List<Map<String, String>>) root.getOrDefault("streams", Collections.emptyList());

            Map<String, String> result = new LinkedHashMap<>();
            for (Map<String, String> entry : streams) {
                String groupId    = entry.get("groupId");
                String artifactId = entry.get("artifactId");
                String version    = entry.get("version");
                if (groupId != null && artifactId != null && version != null) {
                    result.put(groupId + ":" + artifactId, version);
                }
            }
            return Collections.unmodifiableMap(result);
        }
    }
}
