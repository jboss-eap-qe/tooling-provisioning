/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.qa.tooling.sbom.verification.fluent;

import org.cyclonedx.model.Bom;
import org.cyclonedx.parsers.JsonParser;
import org.wildfly.qa.tooling.sbom.component.Component;
import org.wildfly.qa.tooling.sbom.component.ComponentTree;
import org.wildfly.qa.tooling.sbom.result.CheckCategory;
import org.wildfly.qa.tooling.sbom.result.CheckResult;
import org.wildfly.qa.tooling.sbom.result.CheckResults;
import org.wildfly.qa.tooling.sbom.verification.Context;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.zip.GZIPInputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * One check of an SBOM that a JAR embeds against the top-level SBOM: the components that the top-level SBOM
 * nests under the Maven component of that JAR must be the components of the embedded SBOM, one to one, and
 * every one of them must meet a condition. See {@link WithSbom#withBundledSbomCheck}.
 */
final class BundledSbomCheck {

    private final Context context;
    private final String groupId;
    private final String artifactId;
    private final String embeddedSbomPath;
    private final Predicate<Component> componentCheck;
    private final String errorMessage;

    BundledSbomCheck(Context context, String groupId, String artifactId, String embeddedSbomPath,
                     Predicate<Component> componentCheck, String errorMessage) {
        this.context = context;
        this.groupId = groupId;
        this.artifactId = artifactId;
        this.embeddedSbomPath = embeddedSbomPath;
        this.componentCheck = componentCheck;
        this.errorMessage = errorMessage;
    }

    CheckResult run() {
        Optional<Bom> bom = context.bom().get();
        if (bom.isEmpty()) {
            return CheckResults.unavailable(CheckCategory.BUNDLED_SBOM, "the SBOM");
        }
        String purlPrefix = "pkg:maven/" + groupId + "/" + artifactId + "@";
        List<Component> bundlers = ComponentTree.mavenComponents(bom.get().getComponents()).stream()
                .filter(c -> c.purl().startsWith(purlPrefix))
                .toList();
        List<String> issues = new ArrayList<>();
        if (bundlers.isEmpty()) {
            issues.add(prefix() + "no such component in the SBOM");
        }
        for (Component bundler : bundlers) {
            checkBundler(bundler, issues);
        }
        return CheckResults.bundledSbom(issues);
    }

    private void checkBundler(Component bundler, List<String> issues) {
        List<String> locations = bundler.occurrenceLocations();
        if (locations.isEmpty()) {
            issues.add(prefix() + bundler.purl() + " [no location declared, so its JAR cannot be opened]");
            return;
        }
        List<Component> declared = ComponentTree.all(bundler.model().getComponents()).toList();
        for (String location : locations) {
            Path jar = context.root().resolve(location);
            Optional<Bom> embedded = readEmbedded(jar, location, issues);
            if (embedded.isEmpty()) {
                continue;
            }
            List<Component> inJar = ComponentTree.all(embedded.get().getComponents()).toList();
            compare(bundler, location, declared, inJar, issues);
            reject(declared, "in the SBOM", issues);
            reject(inJar, "in " + embeddedSbomPath, issues);
        }
    }

    /** One to one: a purl declared twice needs two components in the embedded SBOM, and the other way round. */
    private void compare(Component bundler, String location, List<Component> declared, List<Component> inJar,
                         List<String> issues) {
        List<String> notYetMatched = inJar.stream()
                .map(Component::purl)
                .filter(purl -> purl != null)
                .collect(Collectors.toCollection(ArrayList::new));
        for (Component component : declared) {
            if (component.purl() != null && !notYetMatched.remove(component.purl())) {
                issues.add(prefix() + component.purl() + " [declared under " + bundler.purl()
                        + ", missing from " + embeddedSbomPath + " of " + location + "]");
            }
        }
        for (String purl : notYetMatched) {
            issues.add(prefix() + purl + " [in " + embeddedSbomPath + " of " + location
                    + ", not declared under " + bundler.purl() + "]");
        }
    }

    private void reject(List<Component> components, String where, List<String> issues) {
        for (Component component : components) {
            boolean accepted;
            try {
                accepted = componentCheck.test(component);
            } catch (RuntimeException e) {
                issues.add(prefix() + purlOf(component) + " [" + errorMessage + " (the check threw "
                        + e.getClass().getSimpleName() + ") " + where + "]");
                continue;
            }
            if (!accepted) {
                issues.add(prefix() + purlOf(component) + " [" + errorMessage + " " + where + "]");
            }
        }
    }

    /** @return the embedded SBOM, or empty after adding the reason to {@code issues} */
    private Optional<Bom> readEmbedded(Path jar, String location, List<String> issues) {
        if (!Files.isRegularFile(jar)) {
            issues.add(prefix() + location + " [JAR not found, so " + embeddedSbomPath + " cannot be read]");
            return Optional.empty();
        }
        try (ZipFile zip = new ZipFile(jar.toFile())) {
            ZipEntry entry = zip.getEntry(embeddedSbomPath);
            if (entry == null) {
                issues.add(prefix() + location + " [no embedded SBOM at " + embeddedSbomPath + "]");
                return Optional.empty();
            }
            try (InputStream raw = zip.getInputStream(entry);
                 InputStream in = embeddedSbomPath.endsWith(".gz") ? new GZIPInputStream(raw) : raw) {
                return Optional.of(new JsonParser().parse(in.readAllBytes()));
            }
        } catch (IOException | org.cyclonedx.exception.ParseException | RuntimeException e) {
            issues.add(prefix() + location + " [" + embeddedSbomPath + " cannot be read: "
                    + e.getClass().getSimpleName() + "]");
            return Optional.empty();
        }
    }

    private static String purlOf(Component component) {
        return component.purl() != null ? component.purl() : "(component without a purl)";
    }

    private String prefix() {
        return "[" + groupId + ":" + artifactId + "] ";
    }
}
