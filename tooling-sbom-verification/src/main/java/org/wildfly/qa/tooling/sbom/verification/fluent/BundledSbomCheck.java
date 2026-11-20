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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;
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
        List<String> issues = new ArrayList<>();
        List<Component> mavenComponents = getMavenComponentsByGroupAndArtifactId(bom.get());
        if (mavenComponents.isEmpty()) {
            issues.add(prefix() + "no such component in the SBOM");
        }
        mavenComponents.forEach(mavenComponent -> checkMavenComponent(mavenComponent, issues));
        return CheckResults.bundledSbom(issues);
    }

    /** @return the Maven components of the SBOM with the group and artifact id of this check */
    private List<Component> getMavenComponentsByGroupAndArtifactId(Bom bom) {
        String purlPrefix = "pkg:maven/" + groupId + "/" + artifactId + "@";
        return ComponentTree.mavenComponents(bom.getComponents()).stream()
                .filter(component -> component.purl().startsWith(purlPrefix))
                .toList();
    }

    /** Compares the components nested under the Maven component with the SBOM embedded in each of its JARs. */
    private void checkMavenComponent(Component mavenComponent, List<String> issues) {
        if (reportIfMavenComponentHasNoJarLocations(mavenComponent, issues)) {
            return;
        }
        List<Component> nestedComponents = ComponentTree.all(mavenComponent.model().getComponents()).toList();
        for (String jarLocation : mavenComponent.occurrenceLocations()) {
            Optional<Bom> embeddedBom = readEmbeddedSbomFromJar(context.root().resolve(jarLocation), jarLocation, issues);
            if (embeddedBom.isEmpty()) {
                continue;
            }
            List<Component> embeddedComponents = ComponentTree.all(embeddedBom.get().getComponents()).toList();
            reportIfComponentIsMissingInEmbeddedSbom(mavenComponent, jarLocation, nestedComponents, embeddedComponents, issues);
            reportIfComponentUnexpectedInEmbeddedSbom(mavenComponent, jarLocation, nestedComponents, embeddedComponents, issues);
            reportIfComponentFailsPredicateCheck(
                    Stream.concat(nestedComponents.stream(), embeddedComponents.stream()).toList(), issues);
        }
    }

    /** @return {@code true} after reporting it, when the SBOM declares no location, so no JAR can be opened */
    private boolean reportIfMavenComponentHasNoJarLocations(Component mavenComponent, List<String> issues) {
        if (mavenComponent.occurrenceLocations().isEmpty()) {
            issues.add(prefix() + mavenComponent.purl() + " [no location declared, so its JAR cannot be opened]");
            return true;
        }
        return false;
    }

    /**
     * Loads the SBOM embedded in a JAR. Reports why it cannot be loaded and returns empty; it does not look
     * at what the SBOM contains.
     */
    private Optional<Bom> readEmbeddedSbomFromJar(Path jarPath, String jarLocation, List<String> issues) {
        if (!Files.isRegularFile(jarPath)) {
            issues.add(prefix() + jarLocation + " [JAR not found, so " + embeddedSbomPath + " cannot be read]");
            return Optional.empty();
        }
        try (ZipFile jar = new ZipFile(jarPath.toFile())) {
            ZipEntry sbomEntry = jar.getEntry(embeddedSbomPath);
            if (sbomEntry == null) {
                issues.add(prefix() + jarLocation + " [no embedded SBOM at " + embeddedSbomPath + "]");
                return Optional.empty();
            }
            try (InputStream entryStream = jar.getInputStream(sbomEntry);
                 InputStream sbomStream = embeddedSbomPath.endsWith(".gz")
                         ? new GZIPInputStream(entryStream) : entryStream) {
                return Optional.of(new JsonParser().parse(sbomStream.readAllBytes()));
            }
        } catch (IOException | org.cyclonedx.exception.ParseException | RuntimeException e) {
            issues.add(prefix() + jarLocation + " [" + embeddedSbomPath + " cannot be read: "
                    + e.getClass().getSimpleName() + "]");
            return Optional.empty();
        }
    }

    /** Reports each component nested under the Maven component that the embedded SBOM lacks, one to one by purl. */
    private void reportIfComponentIsMissingInEmbeddedSbom(Component mavenComponent, String jarLocation,
                                                        List<Component> nestedComponents,
                                                        List<Component> embeddedComponents,
                                                        List<String> issues) {
        for (String purl : purlsMissingFrom(nestedComponents, embeddedComponents)) {
            issues.add(prefix() + purl + " [declared under " + mavenComponent.purl()
                    + ", missing from " + embeddedSbomPath + " of " + jarLocation + "]");
        }
    }

    /** Reports each component of the embedded SBOM that is not nested under the Maven component, one to one by purl. */
    private void reportIfComponentUnexpectedInEmbeddedSbom(Component mavenComponent, String jarLocation,
                                                           List<Component> nestedComponents,
                                                           List<Component> embeddedComponents,
                                                           List<String> issues) {
        for (String purl : purlsMissingFrom(embeddedComponents, nestedComponents)) {
            issues.add(prefix() + purl + " [in " + embeddedSbomPath + " of " + jarLocation
                    + ", not declared under " + mavenComponent.purl() + "]");
        }
    }

    /**
     * Reports each component for which the caller's condition does not hold, or throws. The same line is
     * reported once, so a component that fails in both SBOMs is not listed twice.
     */
    private void reportIfComponentFailsPredicateCheck(List<Component> components, List<String> issues) {
        Set<String> failures = new LinkedHashSet<>();
        for (Component component : components) {
            try {
                if (!componentCheck.test(component)) {
                    failures.add(prefix() + purlOf(component) + " [" + errorMessage + "]");
                }
            } catch (RuntimeException e) {
                failures.add(prefix() + purlOf(component) + " [" + errorMessage + " (the check threw "
                        + e.getClass().getSimpleName() + ")]");
            }
        }
        issues.addAll(failures);
    }

    /**
     * The purls of {@code components} that {@code otherComponents} does not account for. One to one: a purl
     * that occurs twice in {@code components} needs two in {@code otherComponents}. Components without a purl
     * are ignored.
     */
    private static List<String> purlsMissingFrom(List<Component> components, List<Component> otherComponents) {
        List<String> unmatchedPurls = otherComponents.stream()
                .map(Component::purl)
                .filter(Objects::nonNull)
                .collect(Collectors.toCollection(ArrayList::new));
        return components.stream()
                .map(Component::purl)
                .filter(Objects::nonNull)
                .filter(purl -> !unmatchedPurls.remove(purl))
                .toList();
    }

    private static String purlOf(Component component) {
        return component.purl() != null ? component.purl() : "(component without a purl)";
    }

    private String prefix() {
        return "[" + groupId + ":" + artifactId + "] ";
    }
}
