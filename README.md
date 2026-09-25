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

## Build

From this repository, with Go 1.26 or newer:

```sh
go build -o ocivexwalk ./cmd/ocivexwalk
go test ./...
```

## Scope

The conclusions describe matched VEX assertions for the selected image identity, separately for the old and new feeds. They do not represent a complete RPM scan or predict the final StackRox OSV suppression result. See [MAINTAINING.md](MAINTAINING.md) when updating the matching logic.
