# OCI VEX Walk

`ocivexwalk` explains, step by step, how an image and CVE match Red Hat's old and new VEX documents. It shows the evidence behind a conclusion for each feed.

## Run

Obtain a compiled `ocivexwalk` binary from your build or release process. Image pulls require `skopeo` and network access.

```sh
ocivexwalk --image registry.example.com/team/image:tag --cve CVE-2024-24786
```

The default platform is `linux/amd64` on every host. Use `--platform os/arch[/variant]` to change it. Progress goes to stderr, leaving stdout available for a report file.

For a standalone HTML report, use:

```sh
ocivexwalk --image registry.example.com/team/image:tag --cve CVE-2024-24786 \
  --format html --embed-vex-docs > report.html
```

`--embed-vex-docs` is optional. It includes the loaded VEX documents and any loaded name map for download; without it, the report is smaller. Step 4 links the document URLs. The old feed is Red Hat's [`/vex/`](https://security.access.redhat.com/data/csaf/v2/vex/); the new feed is [`/vex-feed/`](https://security.access.redhat.com/data/csaf/v2/vex-feed/), the default used by the referenced Claircore updater.

For a concise spreadsheet row, use CSV:

```sh
ocivexwalk --image registry.example.com/team/image:tag --cve CVE-2024-24786 \
  --format csv > evidence.csv
```

The single-image CSV contains one header and one result row: image, CVE, detected name and CPE, and old and new VEX conclusions. `detected_name` lists the package names eligible for Claircore matching, separated by `; ` when there is more than one. For `labels.json`, that is its `name`. For a legacy Dockerfile, it includes the `com.redhat.component` source name and the binary/ancestry names resolved through the container name mapping; the Dockerfile `name` is used directly only when the mapping has no entry. If both identities are eligible on the latest RHCC layer, the cell contains their distinct names. An empty CPE is expected for a legacy GoldRepo identity, where Claircore does not compare advisory CPEs.

When no assertion matches, the conclusion names the deepest check reached: OCI name, product CPE, linked CSAF status, or Claircore assertion. For a legacy Dockerfile, `No matching assertion — no eligible package name found` means no OCI component name in that feed matched the source component or any mapped binary/ancestry name; Step 9 lists the checked names. For example, `No matching assertion — name/CPE not linked` means the name and CPE each matched a VEX product, but no status relationship joined them. These labels describe VEX matching; they do not establish that the image is fixed or safe.

The two feeds are evaluated independently. `Unavailable` means that feed's document could not be loaded; `Incomplete` means its loaded document or an eligible image identity could not be fully analyzed. If the image has no usable RHCC identity, both feeds are `Incomplete` because neither can be checked. The conclusion names the image stop cause when known, such as `Incomplete — labels.json missing created` or `Incomplete — invalid labels.json`. The HTML verdict also explains why an older identity cannot be used.

When an affected or not-affected assertion matches, the text and HTML verdict name the image identity that produced it. A `legacy Dockerfile` match uses GoldRepo and does not compare the advisory CPE; its eligible package names come from the Dockerfile and the container name mapping. The HTML verdict links directly to status relationships, matched assertions, and conclusions. For large advisories, long evidence lists start collapsed so those later steps remain easy to reach.

A Step 7 `MATCH` means a VEX component and advisory product are linked by a status row; it is not yet a matched Claircore assertion. Claircore emits OCI `known_affected` as a **source-package** assertion. If a legacy status names a mapped binary/ancestry package while `com.redhat.component` gives the source package a different name, Step 8 cannot match that row. The report calls this a source package name mismatch in Step 7, Step 8, and the conclusion.

To enrich a CSV spreadsheet, identify its image and CVE columns by header name, Excel letter, or 1-based position:

```sh
ocivexwalk --input-csv findings.csv --image-column Image --cve-column CVE \
  > findings-with-vex.csv
```

Input columns and row order are preserved. The tool appends `detected_name`, `detected_cpe`, `old_vex_conclusion`, `new_vex_conclusion`, and `processing_error`, or updates those columns if they already exist. `--input-csv` implies CSV output; `--image-column` and `--cve-column` default to headers named `image` and `cve`. For a local archive in an image cell, use `docker-archive:/path/to/image.tar`. The tool pulls each distinct image once, loads each distinct VEX document source once, and analyzes each distinct image/CVE pair once per invocation. Progress on stderr shows distinct images completed versus total distinct images, counting an image complete after all its unique CVEs finish.

The header and each completed row are flushed to stdout immediately. A failed row has blank VEX conclusions and an explanation in `processing_error`; processing continues with later rows. Failed pulls are cached too, so repeated rows do not retry the same image. If any rows fail, the command exits with a nonzero status after writing all rows.

## Build

From this repository, with Go 1.26 or newer:

```sh
go build -o ocivexwalk ./cmd/ocivexwalk
go test ./...
```

## Scope

The conclusions describe matched VEX assertions for the selected image identity, separately for the old and new feeds. They do not represent a complete RPM scan or predict the final StackRox OSV suppression result. See [MAINTAINING.md](MAINTAINING.md) when updating the matching logic.
