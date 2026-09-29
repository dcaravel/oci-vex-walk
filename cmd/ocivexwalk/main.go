// ocivexwalk explains RHCC image evidence and Red Hat VEX matching in terminal order.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dcaravel/oci-vex-walk/internal/finder"
	"github.com/dcaravel/oci-vex-walk/internal/walk"
	"github.com/quay/claircore/pkg/rhctag"
	"github.com/quay/claircore/rhel/dockerfile"
	"github.com/quay/claircore/rhel/rhcc"
	"github.com/spf13/cobra"
)

type options struct {
	image, archive, cve, oldDocument, newDocument, nameToReposMap, platform, format string
	inputCSV, imageColumn, cveColumn                                                string
	verbose                                                                         bool
	embedVEXDocs                                                                    bool
	progress                                                                        io.Writer
	summary                                                                         *walkSummary
	documents                                                                       *[]capturedDocument
	documentCache                                                                   map[string][]byte
}

type capturedDocument struct {
	Name, Source, Filename, CapturedAt, SHA256 string
	Data                                       []byte
}

type synchronizedWriter struct {
	mu  sync.Mutex
	out io.Writer
}

func (w *synchronizedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.out.Write(p)
}

var cvePattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

const defaultPlatform = "linux/amd64"

const redHatVEXBaseURL = "https://security.access.redhat.com/data/csaf/v2/"

func redHatVEXDocumentURL(cve, feed string) string {
	year := strings.Split(cve, "-")[1]
	return redHatVEXBaseURL + feed + "/" + year + "/" + strings.ToLower(cve) + ".json"
}

type documentReport struct {
	name, identity string
	report         *finder.Report
}

func section(out io.Writer, number int, title string) {
	fmt.Fprintf(out, "\nStep %d — %s\n", number, title)
}

func (o options) progressStep(number int, activity string) {
	if o.progress != nil {
		fmt.Fprintf(o.progress, "[%d/9] %s\n", number, activity)
	}
}

func (o options) progressTask(number int, activity string, work func() error) error {
	o.progressStep(number, activity)
	if o.progress == nil {
		return work()
	}
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		start := time.Now()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				fmt.Fprintf(o.progress, "[%d/9] Still %s (%s elapsed)\n", number, strings.ToLower(activity), time.Since(start).Round(time.Second))
			}
		}
	}()
	err := work()
	close(done)
	<-stopped
	return err
}

func readDocument(ctx context.Context, client *http.Client, source string) ([]byte, error) {
	var reader io.ReadCloser
	if strings.HasPrefix(source, "https://") || strings.HasPrefix(source, "http://") {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("HTTP %s", resp.Status)
		}
		reader = resp.Body
	} else {
		f, err := os.Open(source)
		if err != nil {
			return nil, err
		}
		reader = f
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

func (o options) loadDocument(ctx context.Context, client *http.Client, source string) ([]byte, error) {
	if data, ok := o.documentCache[source]; ok {
		return data, nil
	}
	data, err := readDocument(ctx, client, source)
	if err == nil && o.documentCache != nil {
		o.documentCache[source] = data
	}
	return data, err
}

func main() {
	if err := newCommand().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "ocivexwalk:", err)
		os.Exit(1)
	}
}

func newCommand() *cobra.Command {
	var o options
	cmd := &cobra.Command{
		Use:           "ocivexwalk",
		Short:         "Walk an OCI image through old and new Red Hat VEX matching",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			o.progress = &synchronizedWriter{out: cmd.ErrOrStderr()}
			if o.embedVEXDocs && o.format != "html" {
				return errors.New("--embed-vex-docs requires --format html")
			}
			if o.inputCSV != "" {
				if o.format != "text" && o.format != "csv" {
					return errors.New("--input-csv outputs CSV and cannot be combined with --format html")
				}
				return runBatchCSV(cmd.Context(), o, cmd.OutOrStdout())
			}
			var summary walkSummary
			o.summary = &summary
			var documents []capturedDocument
			if o.embedVEXDocs {
				o.documents = &documents
			}
			switch o.format {
			case "text":
				var trace bytes.Buffer
				if err := run(cmd.Context(), o, &trace); err != nil {
					return err
				}
				return renderText(cmd.OutOrStdout(), summary, trace.String())
			case "csv":
				var trace bytes.Buffer
				if err := run(cmd.Context(), o, &trace); err != nil {
					return err
				}
				return renderCSV(cmd.OutOrStdout(), o, summary)
			case "html":
				var trace bytes.Buffer
				if err := run(cmd.Context(), o, &trace); err != nil {
					return err
				}
				if err := o.progressTask(9, "Rendering HTML report", func() error {
					return renderHTMLWithSummary(cmd.OutOrStdout(), o, summary, trace.String())
				}); err != nil {
					return err
				}
				o.progressStep(9, "HTML report ready")
				return nil
			default:
				return fmt.Errorf("unknown output format %q; choose text, csv, or html", o.format)
			}
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&o.image, "image", "", "image reference to pull with skopeo")
	flags.StringVar(&o.archive, "archive", "", "local docker-archive tarball instead of pulling")
	flags.StringVar(&o.cve, "cve", "", "CVE to investigate")
	flags.StringVar(&o.oldDocument, "old-document", "", "local old VEX JSON (default: fetch from /vex/)")
	flags.StringVar(&o.newDocument, "new-document", "", "local new VEX JSON (default: fetch from /vex-feed/)")
	flags.StringVar(&o.nameToReposMap, "name-to-repos-map", "", "local JSON map for legacy Dockerfile packages (default: fetch Red Hat's map)")
	flags.StringVar(&o.platform, "platform", defaultPlatform, "platform used when pulling an image, regardless of host")
	flags.StringVar(&o.format, "format", "text", "output format: text, csv, or html")
	flags.StringVar(&o.inputCSV, "input-csv", "", "CSV spreadsheet to enrich; writes CSV to stdout")
	flags.StringVar(&o.imageColumn, "image-column", "image", "input image column: header, Excel letter, or 1-based number")
	flags.StringVar(&o.cveColumn, "cve-column", "cve", "input CVE column: header, Excel letter, or 1-based number")
	flags.BoolVar(&o.embedVEXDocs, "embed-vex-docs", false, "embed loaded VEX documents and legacy name map for download in the HTML report")
	flags.BoolVar(&o.verbose, "verbose", false, "show every rejected component and product")
	return cmd
}

func skopeoCopyArgs(image, archive, platform string) ([]string, error) {
	if platform == "" {
		platform = defaultPlatform
	}
	parts := strings.Split(platform, "/")
	if len(parts) < 2 || len(parts) > 3 || parts[0] == "" || parts[1] == "" || (len(parts) == 3 && parts[2] == "") {
		return nil, fmt.Errorf("invalid platform %q; use os/arch[/variant]", platform)
	}
	args := []string{"--override-os", parts[0], "--override-arch", parts[1]}
	if len(parts) == 3 {
		args = append(args, "--override-variant", parts[2])
	}
	return append(args, "copy", "docker://"+image, "docker-archive:"+archive), nil
}

func legacyVersion(dockerfilePath string) (string, error) {
	nvr := strings.TrimPrefix(path.Base(dockerfilePath), "Dockerfile-")
	last := strings.LastIndexByte(nvr, '-')
	if last < 0 {
		return "", fmt.Errorf("Dockerfile filename has no version-release")
	}
	previous := strings.LastIndexByte(nvr[:last], '-')
	if previous < 0 {
		return "", fmt.Errorf("Dockerfile filename has no NVR structure")
	}
	version := nvr[previous+1:]
	if _, err := rhctag.Parse(version); err != nil {
		return "", fmt.Errorf("Dockerfile version %q is not a Claircore rhctag: %w", version, err)
	}
	return version, nil
}

func run(ctx context.Context, o options, out io.Writer) error {
	if o.cve == "" || (o.image == "") == (o.archive == "") {
		return errors.New("provide -cve and exactly one of -image or -archive")
	}
	cve := strings.ToUpper(strings.TrimSpace(o.cve))
	if !cvePattern.MatchString(cve) {
		return fmt.Errorf("invalid CVE %q", o.cve)
	}
	archive := o.archive
	fmt.Fprintln(out, "Step 1 — Get the image")
	if o.image != "" {
		if o.platform == "" {
			o.platform = defaultPlatform
		}
		f, err := os.CreateTemp("", "vex-oci-image-*.tar")
		if err != nil {
			return err
		}
		archive = f.Name()
		f.Close()
		defer os.Remove(archive)
		fmt.Fprintf(out, "  Pull %s for %s with skopeo.\n", o.image, o.platform)
		args, err := skopeoCopyArgs(o.image, archive, o.platform)
		if err != nil {
			return err
		}
		cmd := exec.CommandContext(ctx, "skopeo", args...)
		cmd.Stderr = o.progress
		if cmd.Stderr == nil {
			cmd.Stderr = os.Stderr
		}
		if err := o.progressTask(1, "Pulling image "+o.image+" for "+o.platform, cmd.Run); err != nil {
			return fmt.Errorf("skopeo copy: %w", err)
		}
	} else {
		fmt.Fprintf(out, "  Read local docker archive %s.\n", archive)
	}
	var image *walk.Image
	err := o.progressTask(1, "Reading image layers", func() error {
		var readErr error
		image, readErr = walk.ReadDockerArchive(archive)
		return readErr
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "  Found %d layers, numbered from base (0) to newest (%d).\n", len(image.Layers), len(image.Layers)-1)

	o.progressStep(2, fmt.Sprintf("Inspecting buildinfo across %d layers", len(image.Layers)))
	section(out, 2, "Inspect buildinfo in each layer")
	type identity struct {
		layer                    int
		path                     string
		data                     []byte
		name, arch, cpe, created string
		valid                    bool
	}
	identities := []identity{}
	type identityIssue struct{ label, detail string }
	issuesByLayer := make(map[int]identityIssue)
	var latestLabelsIssue identityIssue
	foundLabels := false
	var legacy *finder.LegacyIdentity
	legacyMappingUnavailable := false
	legacyLayer := -1
	latestRepo := -1
	for _, layer := range image.Layers {
		if len(layer.Files) == 0 {
			continue
		}
		layerID := strings.TrimSuffix(layer.ArchivePath, ".tar")
		if len(layerID) > 12 {
			layerID = layerID[:12]
		}
		fmt.Fprintf(out, "  Layer %d (%s):\n", layer.Number, layerID)
		if o.verbose {
			fmt.Fprintf(out, "    Archive entry: %s\n", layer.ArchivePath)
		}
		var labels []walk.File
		var dockerfiles []walk.File
		for _, f := range layer.Files {
			if strings.HasSuffix(f.Path, "labels.json") {
				labels = append(labels, f)
			} else {
				dockerfiles = append(dockerfiles, f)
			}
		}
		// Claircore tries root/buildinfo before usr/share/buildinfo.
		sort.Slice(labels, func(i, j int) bool { return labels[i].Path < labels[j].Path })
		if len(labels) > 0 {
			foundLabels = true
			selected := labels[0]
			for _, f := range labels {
				if f.Path == selected.Path {
					fmt.Fprintf(out, "    Selected: %s\n", f.Path)
				} else {
					fmt.Fprintf(out, "    Skipped:  %s (root/buildinfo takes priority)\n", f.Path)
				}
			}
			var raw map[string]json.RawMessage
			if err := json.Unmarshal(selected.Data, &raw); err != nil {
				fmt.Fprintf(out, "    Invalid labels JSON: %v.\n", err)
				issue := identityIssue{"Incomplete — invalid labels.json", fmt.Sprintf("%s in layer %d is invalid JSON: %v", selected.Path, layer.Number, err)}
				issuesByLayer[layer.Number], latestLabelsIssue = issue, issue
			} else {
				value := func(k string) string { var s string; _ = json.Unmarshal(raw[k], &s); return s }
				id := identity{layer: layer.Number, path: selected.Path, data: selected.Data, name: value("name"), arch: value("architecture"), cpe: value("cpe"), created: value("org.opencontainers.image.created")}
				for _, field := range []*string{&id.name, &id.arch, &id.cpe} {
					if unquoted, err := strconv.Unquote(*field); err == nil {
						*field = unquoted
					}
				}
				createdTime, timestampErr := time.Parse(time.RFC3339, id.created)
				id.valid = id.name != "" && id.arch != "" && timestampErr == nil && !createdTime.IsZero()
				var missing []string
				if id.name == "" {
					missing = append(missing, "name")
				}
				if id.arch == "" {
					missing = append(missing, "architecture")
				}
				if id.created == "" {
					missing = append(missing, "created")
				}
				if id.cpe == "" {
					missing = append(missing, "CPE")
				}
				if len(missing) > 0 {
					issue := identityIssue{"Incomplete — labels.json missing " + strings.Join(missing, ", "), fmt.Sprintf("%s in layer %d is missing %s; created means org.opencontainers.image.created.", selected.Path, layer.Number, strings.Join(missing, ", "))}
					issuesByLayer[layer.Number], latestLabelsIssue = issue, issue
				} else if timestampErr != nil || createdTime.IsZero() {
					issue := identityIssue{"Incomplete — labels.json invalid created", fmt.Sprintf("%s in layer %d has an invalid org.opencontainers.image.created timestamp: %q.", selected.Path, layer.Number, id.created)}
					issuesByLayer[layer.Number], latestLabelsIssue = issue, issue
				}
				identities = append(identities, id)
				fmt.Fprintf(out, "    Name:     %s\n    Arch:     %s\n    CPE:      %s\n    Created:  %s\n", id.name, id.arch, id.cpe, id.created)
				if id.cpe != "" {
					latestRepo = layer.Number
					fmt.Fprintln(out, "    RHCC repository: present (from CPE)")
				} else {
					fmt.Fprintln(out, "    RHCC repository: absent (no CPE)")
				}
				if !id.valid {
					fmt.Fprintf(out, "    Package: not emitted; %s\n", issuesByLayer[layer.Number].detail)
				}
			}
		}
		if len(dockerfiles) > 0 {
			chosen := -1
			for i, f := range dockerfiles {
				if chosen < 0 && strings.Count(f.Path, "-") > 1 {
					chosen = i
				}
			}
			for i, f := range dockerfiles {
				if i == chosen {
					labels, err := dockerfile.GetLabels(ctx, strings.NewReader(string(f.Data)))
					if err != nil {
						fmt.Fprintf(out, "    Selected legacy Dockerfile: %s\n      Parse error: %v\n", f.Path, err)
					} else {
						fmt.Fprintf(out, "    Selected legacy Dockerfile: %s\n      Name: %s\n      Component: %s\n      Arch: %s\n", f.Path, labels["name"], labels["com.redhat.component"], labels["architecture"])
						version, versionErr := legacyVersion(f.Path)
						if labels["name"] == "" || labels["com.redhat.component"] == "" || labels["architecture"] == "" || versionErr != nil {
							fmt.Fprintln(out, "      Legacy packages: not emitted; required labels or a valid Dockerfile version are missing.")
						} else {
							legacy = &finder.LegacyIdentity{Path: f.Path, Name: labels["name"], Component: labels["com.redhat.component"], Architecture: labels["architecture"], Version: version}
							legacyLayer = layer.Number
							fmt.Fprintf(out, "      Version: %s\n", version)
						}
					}
				} else {
					fmt.Fprintf(out, "    Skipped legacy Dockerfile: %s\n", f.Path)
				}
			}
			latestRepo = layer.Number // Legacy repository scanner emits GoldRepo for any Dockerfile-*.
			fmt.Fprintln(out, "    RHCC GoldRepo: present (legacy Dockerfile path).")
		}
	}
	if !foundLabels {
		fmt.Fprintln(out, "  No labels.json found. Checking whether a legacy Dockerfile identity can match.")
	}
	if latestRepo < 0 {
		fmt.Fprintln(out, "  No RHCC repository was detected. Claircore's RHCC coalescer has no image identity to match.")
		label, reason := "Incomplete", "No RHCC repository was detected, so this image cannot be checked against either feed."
		if latestLabelsIssue.label != "" {
			label, reason = latestLabelsIssue.label, latestLabelsIssue.detail+" No RHCC repository was detected, so neither feed can be checked."
		}
		fmt.Fprintf(out, "  Stop reason: %s\n", reason)
		o.summary.markImageIncomplete(label, reason)
		o.progressStep(2, "Finished: no RHCC repository was found")
		return nil
	}
	fmt.Fprintf(out, "  Matching layer: %d (latest with RHCC repository content).\n", latestRepo)
	var selected *identity
	for i := range identities {
		id := &identities[i]
		if id.layer < latestRepo {
			fmt.Fprintf(out, "  Layer %d: %s is retained but unmatchable because layer %d is newer.\n", id.layer, id.name, latestRepo)
		}
		if id.layer == latestRepo && id.valid && id.cpe != "" {
			selected = id
		}
	}
	if legacy != nil && legacyLayer != latestRepo {
		fmt.Fprintf(out, "  Legacy Dockerfile from layer %d is unmatchable because layer %d has newer RHCC repository content.\n", legacyLayer, latestRepo)
		legacy = nil
	}
	if o.summary != nil {
		if selected != nil {
			o.summary.DetectedName, o.summary.DetectedCPE = selected.name, selected.cpe
		}
	}
	if selected == nil && legacy == nil {
		fmt.Fprintln(out, "  The latest RHCC layer has no usable labels.json or legacy Dockerfile package identity.")
		label, reason := "Incomplete", "The latest RHCC layer has no usable image identity, so neither feed can be checked."
		if issue := issuesByLayer[latestRepo]; issue.label != "" {
			label, reason = issue.label, issue.detail+" No package identity was emitted on the latest RHCC layer; older identities are unmatchable, so neither feed can be checked."
		}
		fmt.Fprintf(out, "  Stop reason: %s\n", reason)
		o.summary.markImageIncomplete(label, reason)
		o.progressStep(2, "Finished: latest RHCC layer has no usable identity")
		return nil
	}

	o.progressStep(3, "Deriving the image identity")
	section(out, 3, "Derive the image identity")
	if selected != nil {
		created, _ := time.Parse(time.RFC3339, selected.created)
		fmt.Fprintf(out, "  labels.json identity:\n    Source:  layer %d, %s\n    Name:    %s\n    Arch:    %s\n    CPE:     %s\n    Created: %s\n    Version: %d (Unix seconds from created)\n", selected.layer, selected.path, selected.name, selected.arch, selected.cpe, selected.created, created.Unix())
		fmt.Fprintln(out, "    Claircore creates source, binary, and ancestry packages from this identity.")
	}
	if legacy != nil {
		location := o.nameToReposMap
		if location == "" {
			location = rhcc.DefaultName2ReposMappingURL
		}
		client := &http.Client{Timeout: 10 * time.Second}
		var mappingData []byte
		err := o.progressTask(3, "Loading legacy container name mapping from "+location, func() error {
			var readErr error
			mappingData, readErr = o.loadDocument(ctx, client, location)
			return readErr
		})
		if err != nil {
			fmt.Fprintf(out, "  Legacy Dockerfile mapping unavailable at %s: %v. Legacy package matching is incomplete.\n", location, err)
			legacyMappingUnavailable = true
			legacy = nil
		} else {
			var mapping struct {
				Data map[string][]string `json:"data"`
			}
			if err := json.Unmarshal(mappingData, &mapping); err != nil || mapping.Data == nil {
				fmt.Fprintf(out, "  Legacy Dockerfile mapping at %s is invalid; legacy package matching is incomplete.\n", location)
				legacyMappingUnavailable = true
				legacy = nil
			} else {
				repos, found := mapping.Data[legacy.Name]
				if !found {
					repos = []string{legacy.Name}
				}
				legacy.Repositories = repos
				digest := sha256.Sum256(mappingData)
				if o.documents != nil {
					*o.documents = append(*o.documents, capturedDocument{Name: "Legacy name-to-repositories map", Source: location, Filename: "container-name-repos-map.json", CapturedAt: time.Now().UTC().Format(time.RFC3339), SHA256: fmt.Sprintf("%x", digest), Data: mappingData})
				}
				fmt.Fprintf(out, "  Legacy Dockerfile identity:\n    Source: layer %d, %s\n    Name label: %s\n    Component: %s\n    Arch: %s\n    Version: %s\n    Mapping: %s\n    Mapping SHA-256: %x\n", legacyLayer, legacy.Path, legacy.Name, legacy.Component, legacy.Architecture, legacy.Version, location, digest)
				if found {
					fmt.Fprintf(out, "    Map entry: %d repository names\n", len(repos))
				} else {
					fmt.Fprintln(out, "    Map entry: absent; Claircore uses the name label as a binary/ancestry package name.")
				}
				for _, repo := range repos {
					fmt.Fprintf(out, "    Repository name: %s\n", repo)
				}
				fmt.Fprintln(out, "    Repository: GoldRepo; advisory CPE comparison is skipped by Claircore's RHCC matcher.")
			}
		}
	}
	if selected == nil && legacy == nil && !legacyMappingUnavailable {
		return nil
	}

	sources := []struct{ name, local, url string }{
		{"Old VEX feed", o.oldDocument, redHatVEXDocumentURL(cve, "vex")},
		{"New VEX feed", o.newDocument, redHatVEXDocumentURL(cve, "vex-feed")},
	}
	o.progressStep(4, "Loading Red Hat VEX documents")
	section(out, 4, "Load Red Hat VEX documents")
	fmt.Fprintln(out, "  New VEX feed (/vex-feed/) is used by Claircore; Old VEX feed (/vex/) is shown for comparison.")
	type document struct {
		name string
		data []byte
	}
	documents := []document{}
	client := &http.Client{Timeout: 2 * time.Minute}
	for _, src := range sources {
		location := src.url
		if src.local != "" {
			location = src.local
		}
		var data []byte
		err := o.progressTask(4, "Loading "+src.name+" from "+location, func() error {
			var readErr error
			data, readErr = o.loadDocument(ctx, client, location)
			return readErr
		})
		if err != nil {
			fmt.Fprintf(out, "  %s: unavailable: %v.\n    Document source: %s\n", src.name, err, location)
			continue
		}
		fmt.Fprintf(out, "  %s: loaded %d bytes\n    Document source: %s\n", src.name, len(data), location)
		if o.documents != nil {
			sum := sha256.Sum256(data)
			kind := "new"
			if src.name == "Old VEX feed" {
				kind = "old"
			}
			*o.documents = append(*o.documents, capturedDocument{
				Name: src.name, Source: location, Filename: kind + "-vex-" + strings.ToLower(cve) + ".json",
				CapturedAt: time.Now().UTC().Format(time.RFC3339), SHA256: fmt.Sprintf("%x", sum), Data: data,
			})
		}
		documents = append(documents, document{src.name, data})
	}
	if len(documents) == 0 {
		return errors.New("neither VEX document could be loaded")
	}
	reports := []documentReport{}
	for _, identity := range []string{"labels.json", "legacy Dockerfile"} {
		if identity == "labels.json" && selected == nil || identity == "legacy Dockerfile" && legacy == nil && !legacyMappingUnavailable {
			continue
		}
		for _, doc := range documents {
			if identity == "legacy Dockerfile" && legacyMappingUnavailable {
				reports = append(reports, documentReport{name: doc.name, identity: identity, report: &finder.Report{Summary: "Legacy mapping unavailable; matching could not be completed.", Warnings: []string{"The name-to-repositories map could not be loaded, so Claircore's legacy package names are unknown."}}})
				continue
			}
			var report *finder.Report
			err := o.progressTask(4, "Analyzing "+doc.name+" for "+identity, func() error {
				request := finder.Request{CVE: cve, Document: string(doc.data)}
				if identity == "labels.json" {
					request.Labels = string(selected.data)
				} else {
					request.Legacy = legacy
				}
				var analyzeErr error
				report, analyzeErr = finder.Analyze(request)
				return analyzeErr
			})
			if err != nil {
				fmt.Fprintf(out, "  %s / %s: could not analyze document: %v\n", doc.name, identity, err)
				reports = append(reports, documentReport{name: doc.name, identity: identity, report: &finder.Report{Summary: "Matching could not be completed: " + err.Error(), Warnings: []string{err.Error()}}})
				continue
			}
			reports = append(reports, documentReport{name: doc.name, identity: identity, report: report})
		}
	}
	if len(reports) == 0 {
		return errors.New("neither VEX document could be analyzed")
	}
	imageName, imageCPE := "", ""
	matchingNames := make(map[string]bool)
	if selected != nil {
		matchingNames[selected.name] = true
		imageCPE = selected.cpe
	}
	if legacy != nil {
		matchingNames[legacy.Component] = true
		for _, name := range legacy.Repositories {
			if name != "" {
				matchingNames[name] = true
			}
		}
	}
	var names []string
	for name := range matchingNames {
		names = append(names, name)
	}
	sort.Strings(names)
	imageName = strings.Join(names, "; ")
	printReports(out, reports, o, imageName, imageCPE)
	o.progressStep(9, "Analysis complete")
	return nil
}
