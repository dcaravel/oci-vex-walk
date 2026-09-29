# Updating the walkthrough when Claircore or StackRox changes

This repository explains a particular source path through Claircore and StackRox. Update the explanation from the checked-out source, then update the code and all report formats together. Do not infer scanner suppression solely from a VEX status or from the absence of a matched assertion.

## Source checkouts and baseline

For source behavior reviews, you can place optional upstream checkouts at:

```text
../../quay/claircore       Claircore source for comparison
../../stackrox/stackrox    StackRox source for comparison
```

`go.mod` downloads and pins Claircore; neither checkout is needed to build or run the tool. The reference source revisions are Claircore `f0c4b3ad21363025125f8702e476e5b8b0eb2710` and StackRox `92b9d3903d6bf71479241b4f93df7befcfad0b2f`. Treat these as comparison points, not as claims about a future checkout. Before changing logic, record `git -C <checkout> rev-parse HEAD` and `git -C <checkout> status --short` for each checkout used. Review committed changes since the last verified revisions and any local changes. After validating an update, record the new verified revisions here and in the README if it names one. When changing Claircore, update its pinned version in `go.mod` and checksums in `go.sum`.

The CSV output was checked against local Claircore `4b16410062d2ba61ef16354984f8994f1d83d233` and StackRox `067c642e255db1724c1a4ff47d1112ec6e37b142`; both checkouts were clean. Since the reference revisions, the matching and conversion paths above have no committed changes. StackRox has an unrelated feature entry and container Dockerfile changes.

Useful starting commands from this repository root:

```sh
git -C ../../quay/claircore diff f0c4b3ad21363025125f8702e476e5b8b0eb2710..HEAD -- rhel/rhcc rhel/vex internal/matcher/match.go
git -C ../../stackrox/stackrox diff 92b9d3903d6bf71479241b4f93df7befcfad0b2f..HEAD -- scanner pkg/scanners/scannerv4/convert.go pkg/scannerv4/mappers/mappers.go pkg/features/list.go
rg -n 'PackageNotVulnerable|filterNotAffectedVulnerabilities|filterOSVSupersededByRedHatVEX|vex-feed|known_not_affected|FixedInVersion' ../../quay/claircore ../../stackrox/stackrox/scanner ../../stackrox/stackrox/pkg/scanners/scannerv4 ../../stackrox/stackrox/pkg/scannerv4/mappers
```

The upstream paths below are relative to their respective checkout roots. Search by symbol if files move.

| Walk stage | Source of behavior | Code and output here |
| --- | --- | --- |
| Image files and layer identity | Claircore `rhel/rhcc/detector.go`, `scanner.go`, `coalescer.go`; `rhel/dockerfile/` | `internal/walk/image.go`; `cmd/ocivexwalk/main.go` steps 1–3, including the optional name map |
| Which feed is loaded | Claircore `rhel/vex/updater.go`, `fetcher.go`; StackRox `scanner/updater/export.go` and its configuration | `cmd/ocivexwalk/main.go` step 4, document capture, and CLI flags |
| OCI name and product CPE | Claircore `rhel/rhcc/purl.go`, `scanner.go`, `matcher.go`; `rhel/vex/parser.go`, `index.go` | `internal/finder/finder.go` candidate, product, and relationship checks for labels.json and GoldRepo; `cmd/ocivexwalk/format.go` steps 5–7 |
| Assertion and version match | Claircore `rhel/vex/parser.go`, `rhel/rhcc/matcher.go`, `internal/matcher/match.go` | `internal/finder/finder.go` assertion evaluation; `cmd/ocivexwalk/format.go` steps 8–9 and decision labels |
| Report mapping and actual scan filtering | StackRox `scanner/matcher/matcher.go`, `pkg/scannerv4/mappers/mappers.go`, `pkg/scanners/scannerv4/convert.go`, `pkg/features/list.go` | Scope and wording in `README.md`, `cmd/ocivexwalk/format.go`, the CSV row, and the HTML summary |
| HTML presentation | The terminal trace produced above | `cmd/ocivexwalk/html.go` grouping, escaped values, collapsed lists, document downloads, and verdict cards |

## Keep matching evidence separate from scan filtering

Claircore's enriched matcher places affected matches in `PackageVulnerabilities` and inverted, not-affected matches in `PackageNotVulnerable` (`internal/matcher/match.go`). The StackRox mapper passes both into the scanner v4 report (`pkg/scannerv4/mappers/mappers.go`). StackRox then applies two distinct conversion filters in `pkg/scanners/scannerv4/convert.go`, each gated by a feature flag:

1. `ScannerV4RedHatVEXNotAffected` uses not-affected **ancestry** assertions. It removes a package vulnerability only when an assertion and the vulnerability share an alias and the package's layer is at or below the assertion's layer.
2. `ScannerV4SuppressOSVWithRedHatVEX` supersedes an `osv/` vulnerability when a matched `rhel-vex` vulnerability on an RHCC package shares an alias and is at the same or a newer layer.

Check the current source and feature flag defaults again before relying on those statements. This tool traces VEX matching for a selected CPE-backed image identity; it does not load every OSV finding, feature flag, package environment, alias, or layer relationship needed to predict the final StackRox scan output. Keep the top verdict scoped to matched VEX assertions. If adding a true suppression verdict later, first collect and show the missing inputs and reproduce both conversion filters in tests.

Treat the old and new VEX feeds as independent checks. A feed with no loaded document is **Unavailable**; a loaded feed whose matching cannot complete is **Incomplete**. An unusable image identity prevents either check and marks both **Incomplete**. For an image stop at step 2, append the specific labels.json cause to both conclusion labels and explain the missing or invalid field in the trace and HTML verdict. The `created` field means `org.opencontainers.image.created`; Claircore requires it to parse as a nonzero time before emitting a package. A result from one feed must never change the other feed's label.

A `fixed` CSAF row can produce an **Affected** match for an image below the fixed version. A **No matching assertion** label now identifies the deepest failed name, product, status, or assertion check; it is not proof of **Fixed** or **Not affected**. For GoldRepo, say "product" instead of implying Claircore compared advisory CPEs. When affected and inverted assertions both match, keep both visible and label the evidence **Conflicting evidence**. Do not reintroduce the previously removed CEL controls just because Claircore contains CEL code; add capabilities only when requested and when the active StackRox configuration uses them.

When labels.json and a legacy Dockerfile both yield eligible identities, keep each identity's name and repository evidence in its own feed card. The top verdict for a matched affected or not-affected assertion must name which identity matched, including GoldRepo's skipped advisory CPE comparison. Keep direct HTML links to steps 7–9 and collapse long assertion lists so a large CSAF document does not bury the conclusion.

For legacy Dockerfiles, recheck `rhel/rhcc/scanner.go` before changing the path: `findLabels` selects a `root/buildinfo/Dockerfile-*`, `getVR` derives the version from its filename, the mapping's `data` object maps the `name` label to binary/ancestry package names (falling back to `name` when absent), and the scanner emits a source package from `com.redhat.component`. The RHCC matcher bypasses advisory CPE comparison for GoldRepo. The coalescer makes packages from older RHCC repository layers unmatchable. StackRox configures this scanner and passes both affected and not-affected package records through its v4 mapper. Keep a failed map load or analysis visibly **Incomplete** rather than claiming the remaining identities cover the whole image.

The CSV `detected_name` field lists distinct eligible Claircore package names, separated by `; `: `labels.json` `name`, the legacy `com.redhat.component` source name, and mapped legacy binary/ancestry names. The raw legacy Dockerfile `name` is a mapping key and appears as a package name only when the map has no entry or explicitly maps to that same name. When both image identities are eligible, include names from both.

If no component matches on a legacy path, the CSV conclusion says no eligible package name was found; its detailed reason lists all eligible names checked for that feed. This is a feed-local result over the source and mapped binary/ancestry names, including a `labels.json` name when that identity is also eligible. Preserve the labels-only `OCI name not found` label.

Do not equate a Step 7 linked `known_affected` row with a matched assertion. Claircore's VEX parser emits OCI `known_affected` as a source-package vulnerability. A legacy binary/ancestry name can satisfy Step 7's component lookup while differing from the source name in `com.redhat.component`; the matcher then has no source package of that name. Show the source package name mismatch in Step 7, Step 8, and the feed conclusion when all linked rows fail for that reason. Keep the generic linked-status label for other no-assertion cases.

## Update procedure

1. **Trace the change in source.** Identify the exact condition that changed, its input fields, and whether StackRox enables it. Read the corresponding upstream tests and any package or report mapping between Claircore and the final scan output. Record the old and new behavior in a small scenario table before editing.
2. **Update the smallest local logic path.** Change `internal/walk/image.go` or `cmd/ocivexwalk/main.go` for image and feed collection; change `internal/finder/finder.go` for document interpretation and matching; change `cmd/ocivexwalk/format.go` for the explanation and verdict. Prefer calling Claircore's parser and matcher over duplicating their algorithms. Preserve a clear **Incomplete** result when required data is unavailable.
3. **Update all outputs.** Text steps come from `main.go` and `format.go`. HTML consumes that text in `html.go`: it recognizes `Step N —`, the exact `Old VEX feed` / `New VEX feed` headings, `MATCH:` / `SKIP:`, indentation, and field labels. When any of those change, update `formatLine`, `organizeStep`, and the template together. Single-image CSV is one image/CVE row with detected identity and feed conclusions. Batch CSV preserves source columns, fills the same four result fields plus `processing_error`, and flushes each row as it finishes. `batch.go` caches archives and pull failures by image, document bytes by source, and results by image/CVE pair. In step 4, keep the `Document source:` line for each feed so the HTML can link remote URLs and show local paths as code. Keep the top HTML, text, and CSV conclusions consistent with step 9. Show raw values in escaped monospaced markup, keep matched assertions visible, and leave long candidate and non-matching assertion lists expandable.
4. **Add evidence-driven tests.** Use `testdata/demo.json` or a small, saved fixture for each changed branch. Test which assertion matches and why, whether it is affected or inverted, and what the user sees in text and HTML. Include a contrary case that must not match. For a real feed, save the document bytes and SHA-256 instead of making CI depend on a live URL. If conversion filtering changes, compare against StackRox's `pkg/scanners/scannerv4/convert_test.go` cases and test the alias, layer, source updater, and feature flag conditions explicitly.
5. **Verify the walk.** Run `go test ./...` and `go run ./cmd/ocivexwalk --help`. For a representative image or archive, generate text and HTML (`--format html --embed-vex-docs` if preserving feed snapshots), inspect the new and old feed conclusions, and expand the evidence details. Compare the reported behavior with the checked-out source and, when available, a real StackRox scan under known feature flag settings. Update the README's scope and this guide's verified revisions.

Do not edit or commit changes to the external Claircore or StackRox checkouts as part of a walkthrough update unless that is separately requested.
