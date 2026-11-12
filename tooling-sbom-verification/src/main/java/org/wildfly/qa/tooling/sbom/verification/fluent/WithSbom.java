/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.qa.tooling.sbom.verification.fluent;

import org.cyclonedx.exception.ParseException;
import org.cyclonedx.model.Bom;
import org.wildfly.qa.tooling.sbom.component.Component;
import org.wildfly.qa.tooling.sbom.result.CheckCategory;
import org.wildfly.qa.tooling.sbom.result.CheckResult;
import org.wildfly.qa.tooling.sbom.verification.Context;
import org.wildfly.qa.tooling.sbom.verification.Lazy;
import org.wildfly.qa.tooling.sbom.result.CheckResults;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.zip.GZIPInputStream;

/**
 * An installation that is expected to have a valid SBOM. Further conditions on the parsed SBOM can be added
 * with {@link #withBomCheck(Predicate, String)}.
 *
 * <p>The check that the SBOM exists and parses is implicit: it is added to the stack when this stage
 * switches to the next one or verifies. The stage is mutable: {@code withBomCheck} adds to its check stack
 * and returns the same stage.</p>
 */
public final class WithSbom {

    private final Context context;
    private final List<Supplier<CheckResult>> checks;

    public WithSbom(Context context, List<Supplier<CheckResult>> parentChecks) {
        this.context = context;
        this.checks = new ArrayList<>(parentChecks);
    }

    /**
     * Adds a condition on the parsed SBOM. The check fails with {@code errorMessage} when the predicate
     * returns {@code false}. If the SBOM is missing or invalid, the check fails for that reason and the
     * predicate is not called. A predicate that throws makes the check fail; it does not abort the
     * verification. The SBOM is parsed once and shared by all checks of this stage.
     *
     * @param predicate    the condition the SBOM must satisfy
     * @param errorMessage the issue reported when the condition is not met
     * @return this stage
     */
    public WithSbom withBomCheck(Predicate<Bom> predicate, String errorMessage) {
        Objects.requireNonNull(predicate, "predicate");
        Objects.requireNonNull(errorMessage, "errorMessage");
        checks.add(() -> checkBom(predicate, errorMessage));
        return this;
    }

    /**
     * Adds a check of an SBOM that a JAR embeds. Some JARs carry their own SBOM for what they bundle, for
     * example the HAL console ({@code org.jboss.hal:hal-console}), whose npm packages are bundled JavaScript
     * that is not on disk by itself. The top-level SBOM declares those packages as components nested under
     * the Maven component of the JAR. The check fails when:
     * <ul>
     *   <li>the SBOM has no Maven component with that group and artifact, or it declares no location;</li>
     *   <li>the JAR is not on disk, or has no entry at {@code embeddedSbomPath}, or the entry is not a
     *       readable SBOM (this is a failure, not a skipped check);</li>
     *   <li>the components nested under the Maven component and the components of the embedded SBOM are not
     *       the same, compared one to one by purl: a purl that is declared twice needs two components in the
     *       embedded SBOM, and the other way round;</li>
     *   <li>{@code componentCheck} returns {@code false} for a component of either SBOM. A check that throws
     *       counts as {@code false}.</li>
     * </ul>
     * Each issue starts with {@code [groupId:artifactId]}.
     *
     * <p>The JAR is found by the location the SBOM declares, relative to the root of this verification. The
     * condition is the caller's: the tooling knows nothing about npm or any other kind of component. This is
     * opt-in, because only some distributions ship such a JAR. If the SBOM is unavailable the check fails as
     * "not checked". Can be called for any number of JARs.</p>
     *
     * @param groupId          the Maven group of the component, e.g. {@code org.jboss.hal}
     * @param artifactId       the Maven artifactId of the component, e.g. {@code hal-console}
     * @param embeddedSbomPath the path of the SBOM inside the JAR, e.g. {@code META-INF/sbom/npm-bom.cdx.json};
     *                         gunzipped when it ends in {@code .gz}
     * @param componentCheck   the condition every component must meet, for example "the purl is {@code pkg:npm/<module name>@<version>}"
     * @param errorMessage     what is reported for a component that does not meet it
     * @return this stage
     */
    public WithSbom withBundledSbomCheck(String groupId, String artifactId, String embeddedSbomPath,
                                               Predicate<Component> componentCheck, String errorMessage) {
        Objects.requireNonNull(groupId, "groupId");
        Objects.requireNonNull(artifactId, "artifactId");
        Objects.requireNonNull(embeddedSbomPath, "embeddedSbomPath");
        Objects.requireNonNull(componentCheck, "componentCheck");
        Objects.requireNonNull(errorMessage, "errorMessage");
        checks.add(new BundledSbomCheck(context, groupId, artifactId, embeddedSbomPath, componentCheck,
                errorMessage)::run);
        return this;
    }

    /**
     * Also requires the SBOM to conform to the CycloneDX JSON schema of the version it declares. Off by
     * default: the SBOM only has to parse, which accepts documents that strict consumers reject. A
     * schema-invalid SBOM is still parsed, so the other checks keep running. The failure lists the message of
     * every schema error.
     *
     * @return this stage
     */
    public WithSbom withSchemaValidation() {
        checks.add(this::checkSchema);
        return this;
    }

    /**
     * Also requires the SBOM file to be compressed: a complete, intact gzip stream. This is decided from the
     * content, not from the file name: the file must start with the gzip magic bytes and be readable to the
     * end, which also checks the CRC32 and the length stored in the trailer, like {@code gzip -t}. A plain
     * JSON file called {@code .gz}, a truncated or corrupt file all fail with the cause. Off by default: the
     * SBOM may be plain. A file that does not exist fails as the SBOM check does.
     *
     * @return this stage
     */
    public WithSbom withGzipCheck() {
        checks.add(this::checkGzip);
        return this;
    }

    /** Expects the installation to have a valid manifest. */
    public WithManifest withManifest() {
        return new WithManifest(context, stack());
    }

    /** Expects the installation to have no manifest. */
    public WithoutManifest withoutManifest() {
        return new WithoutManifest(context, stack());
    }

    /**
     * Runs the checks of the parents and of this stage.
     *
     * @return one result per check, in the order they ran; never {@code null}
     */
    public List<CheckResult> verify() {
        return context.run(stack());
    }

    /** @return the checks collected so far followed by the implicit check of this stage; a new list */
    public List<Supplier<CheckResult>> stack() {
        List<Supplier<CheckResult>> stack = new ArrayList<>(checks);
        stack.add(this::checkSbomValid);
        return stack;
    }

    /** Fails if the SBOM is missing, cannot be read or is not valid CycloneDX. */
    private CheckResult checkSbomValid() {
        return sbomFailure().orElseGet(() -> CheckResults.passed(CheckCategory.SBOM));
    }

    /** Fails like {@link #checkSbomValid()}, or if the SBOM does not conform to the schema. */
    private CheckResult checkSchema() {
        Optional<CheckResult> failure = sbomFailure();
        if (failure.isPresent()) {
            return failure.get();
        }
        Path file = context.sbomFile().orElseThrow();
        Lazy<List<ParseException>> schemaErrors = context.schemaErrors();
        return schemaErrors.error()
                .map(error -> CheckResults.sbomInvalid(file, error))
                .orElseGet(() -> {
                    List<ParseException> errors = schemaErrors.get().orElseThrow();
                    return errors.isEmpty()
                            ? CheckResults.passed(CheckCategory.SBOM)
                            : CheckResults.sbomSchemaInvalid(file, errors);
                });
    }

    /** Fails if the SBOM file is missing, or is not a complete gzip stream; the SBOM itself is not parsed. */
    private CheckResult checkGzip() {
        Optional<Path> file = context.sbomFile();
        if (file.isEmpty()) {
            return CheckResults.sbomMissing(context.sbomPath());
        }
        try (InputStream in = new GZIPInputStream(Files.newInputStream(file.get()))) {
            in.transferTo(OutputStream.nullOutputStream());
        } catch (IOException e) {
            return CheckResults.sbomNotGzip(file.get(), e.getMessage() != null ? e.getMessage()
                    : e.getClass().getSimpleName());
        }
        return CheckResults.passed(CheckCategory.SBOM);
    }

    /** Fails like {@link #checkSbomValid()}, or if the predicate rejects the SBOM. */
    private CheckResult checkBom(Predicate<Bom> predicate, String errorMessage) {
        Optional<CheckResult> failure = sbomFailure();
        if (failure.isPresent()) {
            return failure.get();
        }
        try {
            return predicate.test(context.bom().get().orElseThrow())
                    ? CheckResults.passed(CheckCategory.SBOM)
                    : CheckResults.sbomCheckFailed(errorMessage);
        } catch (RuntimeException e) {
            return CheckResults.sbomCheckFailed(errorMessage + " (the check threw "
                    + e.getClass().getSimpleName() + ": " + e.getMessage() + ")");
        }
    }

    /** @return why the SBOM is not usable, or empty when it exists and parses */
    private Optional<CheckResult> sbomFailure() {
        Optional<Path> file = context.sbomFile();
        if (file.isEmpty()) {
            return Optional.of(CheckResults.sbomMissing(context.sbomPath()));
        }
        return context.bom().error().map(error -> CheckResults.sbomInvalid(file.get(), error));
    }
}
