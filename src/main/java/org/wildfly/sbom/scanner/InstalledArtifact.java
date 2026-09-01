/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.sbom.scanner;

/**
 * A JAR file (or unversioned JAR) found anywhere in the WildFly installation.
 *
 * @param jarFileName The plain file name as it appears on disk (e.g.
 *                    {@code jboss-logging-3.6.1.Final.jar},
 *                    {@code jboss-modules.jar}).
 * @param jarPath     Absolute path to the file on disk.
 */
public record InstalledArtifact(String jarFileName, String jarPath) {}
