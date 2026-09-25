package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/dcaravel/oci-vex-walk/internal/finder"
	"github.com/quay/claircore"
)

func TestImagePullPlatformDefaultsToLinuxAMD64(t *testing.T) {
	cmd := newCommand()
	flag := cmd.Flags().Lookup("platform")
	if flag == nil || flag.DefValue != defaultPlatform {
		t.Fatalf("platform flag default = %v; want %s", flag, defaultPlatform)
	}
	args, err := skopeoCopyArgs("example.com/image:tag", "image.tar", "")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"--override-os", "linux", "--override-arch", "amd64", "copy", "docker://example.com/image:tag", "docker-archive:image.tar"}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("skopeo args = %v; want %v", args, want)
	}
	args, err = skopeoCopyArgs("example.com/image:tag", "image.tar", "linux/arm64")
	if err != nil {
		t.Fatal(err)
	}
	if args[3] != "arm64" {
		t.Fatalf("platform override was ignored: %v", args)
	}
}

func tarBytes(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	for name, data := range files {
		if err := w.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestOfflineWalkHonorsLatestRHCCLayer(t *testing.T) {
	demo, err := os.ReadFile("../../testdata/demo.json")
	if err != nil {
		t.Fatal(err)
	}
	var input struct {
		Labels   json.RawMessage
		Document json.RawMessage
	}
	if err := json.Unmarshal(demo, &input); err != nil {
		t.Fatal(err)
	}
	manifest, _ := json.Marshal([]map[string]any{{"Layers": []string{"old/layer.tar", "new/layer.tar"}}})
	archive := tarBytes(t, map[string][]byte{
		"manifest.json": manifest,
		"old/layer.tar": tarBytes(t, map[string][]byte{"root/buildinfo/labels.json": input.Labels}),
		"new/layer.tar": tarBytes(t, map[string][]byte{"usr/share/buildinfo/labels.json": input.Labels, "root/buildinfo/Dockerfile-z": []byte("LABEL name=old")}),
	})
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "image.tar")
	docPath := filepath.Join(dir, "doc.json")
	if err := os.WriteFile(archivePath, archive, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(docPath, input.Document, 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err = run(context.Background(), options{archive: archivePath, cve: "CVE-2099-0001", oldDocument: docPath, newDocument: docPath}, &out)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Layer 0: example/widget is retained but unmatchable", "Matching layer: 1", "Step 5 — Match OCI component names", "Image name: \"example/widget\"", "Component names found in VEX:", "Candidate name:", "Image CPE:", "Product CPEs found in VEX:", "Advisory CPE:", "Step 9 — VEX conclusions", "1 affected, 1 not affected", "Old VEX feed", "New VEX feed"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in output:\n%s", want, out.String())
		}
	}
	for _, line := range strings.Split(out.String(), "\n") {
		if strings.Contains(line, "Step ") && strings.Contains(line, " — ") && !strings.HasPrefix(line, "Step ") {
			t.Fatalf("misaligned step heading: %q", line)
		}
	}
	if strings.Count(out.String(), "Step 5 —") != 1 {
		t.Fatal("step 5 should appear once across both feeds")
	}
	var cobraOut bytes.Buffer
	var progress bytes.Buffer
	cmd := newCommand()
	cmd.SetOut(&cobraOut)
	cmd.SetErr(&progress)
	cmd.SetArgs([]string{"--archive", archivePath, "--cve", "CVE-2099-0001", "--old-document", docPath, "--new-document", docPath})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cobraOut.String(), "Step 9 — VEX conclusions") {
		t.Fatal("Cobra long flags did not run the walkthrough")
	}
	if !strings.HasPrefix(cobraOut.String(), "Conclusion (New VEX feed): Conflicting evidence\n") {
		t.Fatalf("text verdict is not first or is ambiguous:\n%s", cobraOut.String())
	}
	for _, want := range []string{"[1/9] Reading image layers", "[4/9] Loading Old VEX feed", "[5/9] Matching component names", "[9/9] Analysis complete"} {
		if !strings.Contains(progress.String(), want) {
			t.Errorf("progress missing %q:\n%s", want, progress.String())
		}
	}
	if strings.Contains(cobraOut.String(), "[1/9]") {
		t.Fatal("progress leaked into report output")
	}
	var htmlOut bytes.Buffer
	progress.Reset()
	htmlCommand := newCommand()
	htmlCommand.SetOut(&htmlOut)
	htmlCommand.SetErr(&progress)
	htmlCommand.SetArgs([]string{"--archive", archivePath, "--cve", "CVE-2099-0001", "--old-document", docPath, "--new-document", docPath, "--format", "html"})
	if err := htmlCommand.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"<!doctype html>", "<title>CVE-2099-0001 | VEX walkthrough</title>", `id="step-1"`, `id="step-9"`, "VEX conclusions", "example/widget"} {
		if !strings.Contains(htmlOut.String(), want) {
			t.Errorf("HTML missing %q", want)
		}
	}
	if got := strings.Count(htmlOut.String(), `class="feed-grid"`); got != 6 {
		t.Errorf("HTML has %d feed sections; want 6 for steps 4–9", got)
	}
	if !strings.Contains(htmlOut.String(), `class="layer-card"`) || !strings.Contains(htmlOut.String(), `class="evidence-card"`) {
		t.Error("HTML is missing grouped layer or matching evidence cards")
	}
	if !strings.Contains(htmlOut.String(), `<details class="value-list">`) || strings.Contains(htmlOut.String(), `<details class="value-list" open`) || !strings.Contains(progress.String(), "[9/9] HTML report ready") {
		t.Error("HTML output is missing compared values or stderr progress")
	}
	if !strings.Contains(htmlOut.String(), `<div class="decision-card conflict" data-feed="new"><p class="decision-source">New VEX feed`) || strings.Index(htmlOut.String(), "Conflicting evidence") > strings.Index(htmlOut.String(), `id="step-1"`) {
		t.Error("current-feed verdict is missing from the top of HTML")
	}
	if strings.Contains(htmlOut.String(), "[1/9]") {
		t.Fatal("progress leaked into HTML")
	}
	if strings.Contains(htmlOut.String(), `id="captured-documents"`) || strings.Contains(htmlOut.String(), "data:application/gzip;base64,") || strings.Contains(htmlOut.String(), `data-download-json data-source-id=`) {
		t.Fatal("the default HTML report unexpectedly embedded VEX documents")
	}
	var embeddedOut bytes.Buffer
	embeddedCommand := newCommand()
	embeddedCommand.SetOut(&embeddedOut)
	embeddedCommand.SetErr(io.Discard)
	embeddedCommand.SetArgs([]string{"--archive", archivePath, "--cve", "CVE-2099-0001", "--old-document", docPath, "--new-document", docPath, "--format", "html", "--embed-vex-docs"})
	if err := embeddedCommand.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(embeddedOut.String(), `id="captured-documents"`) || strings.Count(embeddedOut.String(), `Download compressed copy (.json.gz)`) != 2 || strings.Count(embeddedOut.String(), `>Download JSON</button>`) != 2 || !strings.Contains(embeddedOut.String(), "DecompressionStream('gzip')") {
		t.Fatal("embedded report does not offer both VEX snapshots")
	}
	wantHash := sha256.Sum256(input.Document)
	if strings.Count(embeddedOut.String(), fmt.Sprintf("%x", wantHash)) != 2 {
		t.Fatal("embedded report is missing the original document checksums")
	}
	const marker = `href="data:application/gzip;base64,`
	parts := strings.Split(embeddedOut.String(), marker)
	if len(parts) != 3 {
		t.Fatalf("found %d embedded gzip payloads; want 2", len(parts)-1)
	}
	for _, part := range parts[1:] {
		encoded, _, ok := strings.Cut(part, `"`)
		if !ok {
			t.Fatal("embedded gzip URL was not terminated")
		}
		compressed, err := base64.StdEncoding.DecodeString(html.UnescapeString(encoded))
		if err != nil {
			t.Fatal(err)
		}
		reader, err := gzip.NewReader(bytes.NewReader(compressed))
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		if err := reader.Close(); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decoded, input.Document) {
			t.Fatal("embedded VEX snapshot differs from the loaded document")
		}
	}
	var changed map[string]any
	if err := json.Unmarshal(input.Document, &changed); err != nil {
		t.Fatal(err)
	}
	vulnerabilities := changed["vulnerabilities"].([]any)
	status := vulnerabilities[0].(map[string]any)["product_status"].(map[string]any)
	delete(status, "known_not_affected")
	newDocument, err := json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	newDocPath := filepath.Join(dir, "new.json")
	if err := os.WriteFile(newDocPath, newDocument, 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	err = run(context.Background(), options{archive: archivePath, cve: "CVE-2099-0001", oldDocument: docPath, newDocument: newDocPath}, &out)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Step 9 — VEX conclusions", "Matched assertions: 1 affected, 1 not affected", "Matched assertions: 1 affected, 0 not affected", "Conclusion: Conflicting evidence", "Conclusion: Affected"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing feed conclusion %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "Comparison:") || strings.Contains(out.String(), "Old VEX feed only:") {
		t.Fatal("conclusion still contains a cross-feed comparison")
	}
}

func TestLegacyDockerfileWalkUsesNameMapping(t *testing.T) {
	demo, err := os.ReadFile("../../testdata/demo.json")
	if err != nil {
		t.Fatal(err)
	}
	var input struct{ Labels, Document json.RawMessage }
	if err := json.Unmarshal(demo, &input); err != nil {
		t.Fatal(err)
	}
	manifest, _ := json.Marshal([]map[string]any{{"Layers": []string{"legacy/layer.tar"}}})
	archive := tarBytes(t, map[string][]byte{
		"manifest.json": manifest,
		"legacy/layer.tar": tarBytes(t, map[string][]byte{
			"root/buildinfo/Dockerfile-example-legacy-v4.13.0-1": []byte("FROM scratch\nLABEL name=\"example/legacy\"\nLABEL com.redhat.component=\"example-source-container\"\nLABEL architecture=\"x86_64\"\n"),
		}),
	})
	dir := t.TempDir()
	archivePath, docPath, mapPath := filepath.Join(dir, "image.tar"), filepath.Join(dir, "vex.json"), filepath.Join(dir, "map.json")
	for path, data := range map[string][]byte{
		archivePath: archive,
		docPath:     input.Document,
		mapPath:     []byte(`{"data":{"example/legacy":["example/widget"]}}`),
	} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	var trace bytes.Buffer
	var summary walkSummary
	var captured []capturedDocument
	if err := run(context.Background(), options{archive: archivePath, cve: "CVE-2099-0001", oldDocument: docPath, newDocument: docPath, nameToReposMap: mapPath, summary: &summary, documents: &captured}, &trace); err != nil {
		t.Fatal(err)
	}
	if len(captured) != 3 || captured[0].Filename != "container-name-repos-map.json" || summary.Current.Label != "Conflicting evidence" {
		t.Fatalf("legacy source capture or combined conclusion missing: %d captures, current %q", len(captured), summary.Current.Label)
	}
	for _, want := range []string{"No labels.json found", "Legacy Dockerfile identity:", "Repository name: example/widget", "Names eligible for GoldRepo matching: example-source-container, example/widget", "GoldRepo: advisory CPE is not compared", "Image repository: GoldRepo", "Matched assertions: 1 affected, 1 not affected", "Conclusion: Conflicting evidence"} {
		if !strings.Contains(trace.String(), want) {
			t.Errorf("legacy trace missing %q:\n%s", want, trace.String())
		}
	}
	var page bytes.Buffer
	if err := renderHTMLWithSummary(&page, options{cve: "CVE-2099-0001", documents: &captured}, summary, trace.String()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(page.String(), `<p class="feed-identity">Identity: <code class="entry-code">legacy Dockerfile</code></p>`) || !strings.Contains(page.String(), "GoldRepo") || !strings.Contains(page.String(), "container-name-repos-map.json") || !strings.Contains(page.String(), `<strong>Conflicting evidence</strong>`) {
		t.Fatal("HTML report omitted legacy matching evidence")
	}
	trace.Reset()
	summary = walkSummary{}
	if err := run(context.Background(), options{archive: archivePath, cve: "CVE-2099-0001", oldDocument: docPath, newDocument: docPath, nameToReposMap: filepath.Join(dir, "missing.json"), summary: &summary}, &trace); err != nil {
		t.Fatal(err)
	}
	if summary.Current.Label != "Incomplete" || !strings.Contains(trace.String(), "Legacy Dockerfile mapping unavailable") {
		t.Fatal("missing map must not produce a definitive VEX conclusion")
	}
	bothArchive := tarBytes(t, map[string][]byte{
		"manifest.json": manifest,
		"legacy/layer.tar": tarBytes(t, map[string][]byte{
			"root/buildinfo/labels.json":                         input.Labels,
			"root/buildinfo/Dockerfile-example-legacy-v4.13.0-1": []byte("FROM scratch\nLABEL name=\"example/legacy\"\nLABEL com.redhat.component=\"example-source-container\"\nLABEL architecture=\"x86_64\"\n"),
		}),
	})
	if err := os.WriteFile(archivePath, bothArchive, 0600); err != nil {
		t.Fatal(err)
	}
	trace.Reset()
	summary = walkSummary{}
	if err := run(context.Background(), options{archive: archivePath, cve: "CVE-2099-0001", oldDocument: docPath, newDocument: docPath, nameToReposMap: mapPath, summary: &summary}, &trace); err != nil {
		t.Fatal(err)
	}
	if summary.Current.Label != "Conflicting evidence" ||
		!strings.Contains(trace.String(), "Identity: labels.json: 1 affected, 1 not affected") ||
		!strings.Contains(trace.String(), "Identity: legacy Dockerfile: 1 affected, 1 not affected") ||
		!strings.Contains(trace.String(), "Matched assertions: 2 affected, 2 not affected") {
		t.Fatal("combined report did not preserve both eligible Claircore identities")
	}
	if err := os.WriteFile(mapPath, []byte(`{"data":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	trace.Reset()
	if err := run(context.Background(), options{archive: archivePath, cve: "CVE-2099-0001", oldDocument: docPath, newDocument: docPath, nameToReposMap: mapPath}, &trace); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(trace.String(), "Map entry: absent; Claircore uses the name label") ||
		!strings.Contains(trace.String(), "Identity: legacy Dockerfile: 0 affected, 0 not affected") {
		t.Fatal("missing map entry did not fall back to the Dockerfile name label")
	}
}

func TestLegacyDockerfileInOlderLayerCannotMatch(t *testing.T) {
	demo, err := os.ReadFile("../../testdata/demo.json")
	if err != nil {
		t.Fatal(err)
	}
	var input struct{ Labels, Document json.RawMessage }
	if err := json.Unmarshal(demo, &input); err != nil {
		t.Fatal(err)
	}
	manifest, _ := json.Marshal([]map[string]any{{"Layers": []string{"old/layer.tar", "new/layer.tar"}}})
	archive := tarBytes(t, map[string][]byte{
		"manifest.json": manifest,
		"old/layer.tar": tarBytes(t, map[string][]byte{
			"root/buildinfo/Dockerfile-example-legacy-v4.13.0-1": []byte("FROM scratch\nLABEL name=\"example/legacy\"\nLABEL com.redhat.component=\"example-source-container\"\nLABEL architecture=\"x86_64\"\n"),
		}),
		"new/layer.tar": tarBytes(t, map[string][]byte{"root/buildinfo/labels.json": input.Labels}),
	})
	dir := t.TempDir()
	archivePath, docPath := filepath.Join(dir, "image.tar"), filepath.Join(dir, "vex.json")
	if err := os.WriteFile(archivePath, archive, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(docPath, input.Document, 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err = run(context.Background(), options{archive: archivePath, cve: "CVE-2099-0001", oldDocument: docPath, newDocument: docPath, nameToReposMap: filepath.Join(dir, "missing-map.json")}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Legacy Dockerfile from layer 0 is unmatchable") || strings.Contains(out.String(), "Legacy Dockerfile identity:") || strings.Contains(out.String(), "Legacy Dockerfile mapping unavailable") {
		t.Fatalf("older legacy identity should not load the map or match:\n%s", out.String())
	}
}

func TestReadDocumentBeyondOld32MiBLimit(t *testing.T) {
	const size = 33 << 20
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("x"), size))), ContentLength: size}, nil
	})}
	data, err := readDocument(context.Background(), client, "https://example.test/legacy.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != size {
		t.Fatalf("read %d bytes; want %d", len(data), size)
	}
}

func TestReadDocumentDoesNotRejectLargeDeclaredLength(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    http.StatusOK,
			ContentLength: 129 << 20,
			Body:          io.NopCloser(strings.NewReader(`{"document":"fixture"}`)),
		}, nil
	})}
	data, err := readDocument(context.Background(), client, "https://example.test/large.json")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"document":"fixture"}` {
		t.Fatalf("unexpected body: %s", data)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestInvalidCVE(t *testing.T) {
	var out bytes.Buffer
	if err := run(context.Background(), options{archive: "unused", cve: "CVE-"}, &out); err == nil {
		t.Fatal("expected CVE validation error")
	}
}

func TestCELFlagIsUnavailable(t *testing.T) {
	cmd := newCommand()
	cmd.SetArgs([]string{"--cel", "true"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "unknown flag") {
		t.Fatalf("expected unknown CEL flag, got %v", err)
	}
}

func TestHTMLFormatEscapesDocumentTextAndHandlesPartialTrace(t *testing.T) {
	var out bytes.Buffer
	trace := "Step 1 — Get the image\n  Image: <script>alert(1)</script>\n"
	if err := renderHTML(&out, options{cve: "CVE-2099-0001", image: "bad<script>"}, trace); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "<script>alert(1)</script>") || !strings.Contains(out.String(), "&lt;script&gt;") {
		t.Fatal("HTML report did not escape image or trace values")
	}
	if !strings.Contains(out.String(), `id="step-1"`) {
		t.Fatal("partial walkthrough was not rendered")
	}
	if !strings.Contains(out.String(), `<strong>Incomplete</strong>`) {
		t.Fatal("partial walkthrough should have an incomplete top verdict")
	}
}

func TestHTMLFeedOrderAndSelector(t *testing.T) {
	trace := "Step 4 — Load Red Hat VEX documents\n" +
		"  Old VEX feed: loaded 10 bytes\n    Document source: https://security.access.redhat.com/data/csaf/v2/vex/2099/cve-2099-0001.json\n" +
		"  New VEX feed: loaded 10 bytes\n    Document source: https://security.access.redhat.com/data/csaf/v2/vex-feed/2099/cve-2099-0001.json\n" +
		"Step 9 — VEX conclusions\n" +
		"  Old VEX feed\n    Conclusion: Not affected\n" +
		"  New VEX feed\n    Conclusion: Affected\n"
	documents := []capturedDocument{
		{Name: "Old VEX feed", Filename: "old.json", Data: []byte(`{}`)},
		{Name: "New VEX feed", Filename: "new.json", Data: []byte(`{}`)},
		{Name: "Legacy name-to-repositories map", Filename: "map.json", Data: []byte(`{}`)},
	}
	var out bytes.Buffer
	if err := renderHTMLWithSummary(&out, options{cve: "CVE-2099-0001", documents: &documents}, walkSummary{}, trace); err != nil {
		t.Fatal(err)
	}
	html := out.String()
	oldCard := strings.Index(html, `data-feed="old"><p class="decision-source">Old VEX feed`)
	newCard := strings.Index(html, `data-feed="new"><p class="decision-source">New VEX feed`)
	if oldCard < 0 || newCard < 0 || oldCard >= newCard {
		t.Fatal("header decisions are not in old-then-new order")
	}
	for _, want := range []string{
		`href="https://security.access.redhat.com/data/csaf/v2/vex/2099/cve-2099-0001.json">Old VEX feed</a>`,
		`href="https://security.access.redhat.com/data/csaf/v2/vex-feed/2099/cve-2099-0001.json">New VEX feed</a>`,
		`<a class="entry-link" href="https://security.access.redhat.com/data/csaf/v2/vex/2099/cve-2099-0001.json"><code class="entry-code">https://security.access.redhat.com/data/csaf/v2/vex/2099/cve-2099-0001.json</code></a>`,
		`<a class="entry-link" href="https://security.access.redhat.com/data/csaf/v2/vex-feed/2099/cve-2099-0001.json"><code class="entry-code">https://security.access.redhat.com/data/csaf/v2/vex-feed/2099/cve-2099-0001.json</code></a>`,
		`Step 4 shows the document source actually loaded for this run`,
		`data-feed-choice="both" aria-pressed="true"`,
		`data-feed-choice="old" aria-pressed="false"`,
		`data-feed-choice="new" aria-pressed="false"`,
		`document.documentElement.dataset.feedView = button.dataset.feedChoice`,
		`class="document-card" data-feed="old"`,
		`class="document-card" data-feed="new"`,
		`class="document-card" data-feed="shared"`,
		`class="feed-card" data-feed="old"`,
		`class="feed-card" data-feed="new"`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("feed explanation or selector HTML missing %q", want)
		}
	}
	if strings.Contains(html, "Legacy VEX feed") || strings.Contains(html, "Current VEX feed") {
		t.Fatal("HTML mixes old/new feed names with legacy/current feed names")
	}
	if strings.Contains(html, "Comparison:") || strings.Contains(html, "data-feed-comparison") {
		t.Fatal("cross-feed conclusion comparison is still present")
	}
}

func TestStep4LocalDocumentSourceIsNotLinked(t *testing.T) {
	trace := "Step 4 — Load Red Hat VEX documents\n" +
		"  Old VEX feed: loaded 10 bytes\n    Document source: /tmp/old.json\n" +
		"  New VEX feed: unavailable: file not found.\n    Document source: /tmp/new.json\n"
	var out bytes.Buffer
	if err := renderHTMLWithSummary(&out, options{cve: "CVE-2099-0001"}, walkSummary{}, trace); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/tmp/old.json", "/tmp/new.json"} {
		if !strings.Contains(out.String(), `<code class="entry-code">`+path+`</code>`) || strings.Contains(out.String(), `href="`+path+`"`) {
			t.Errorf("local document source %q should be code, not a link", path)
		}
	}
}

func TestHTMLFormatsImageLayerAndIdentityValuesAsCode(t *testing.T) {
	trace := "Step 1 — Get the image\n" +
		"  Pull quay.io/example/image@sha256:abc for linux/amd64 with skopeo.\n" +
		"Step 2 — Inspect buildinfo in each layer\n" +
		"  Layer 1: example/widget is retained but unmatchable because layer 2 is newer.\n" +
		"  Matching layer: 2 (latest with RHCC repository content).\n" +
		"Step 5 — Match OCI component names\n" +
		"  New VEX feed: 1 component matches\n    Identity: labels.json\n" +
		"Step 6 — Match product CPEs\n  New VEX feed: 1 product matches\n    Identity: labels.json\n" +
		"Step 7 — Follow CSAF status relationships\n  New VEX feed: 1 status matches\n    Identity: labels.json\n" +
		"Step 8 — Check Claircore assertions\n  New VEX feed: 1 assertion matches\n    Identity: labels.json\n" +
		"Step 9 — VEX conclusions\n" +
		"  New VEX feed\n    Identity: labels.json: 1 affected, 0 not affected\n"
	var out bytes.Buffer
	if err := renderHTML(&out, options{cve: "CVE-2099-0001"}, trace); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`Pull <code class="entry-code">quay.io/example/image@sha256:abc</code> for <code class="entry-code">linux/amd64</code> with skopeo.`,
		`Layer <code class="entry-code">1</code>: <code class="entry-code">example/widget</code> is retained but unmatchable because layer <code class="entry-code">2</code> is newer.`,
		`<span class="entry-label">Matching layer</span><span class="entry-value"><code class="entry-code">2</code> (latest with RHCC repository content).</span>`,
		`<p class="feed-identity">Identity: <code class="entry-code">labels.json</code></p>`,
		`<span class="entry-label">Identity</span><span class="entry-value"><code class="entry-code">labels.json</code>: 1 affected, 0 not affected</span>`,
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("HTML did not format direct value as code: %s", want)
		}
	}
	if got := strings.Count(out.String(), `<p class="feed-identity">Identity: <code class="entry-code">labels.json</code></p>`); got != 4 {
		t.Errorf("identity was code formatted in %d feed steps, want 4", got)
	}
}

func TestDecisionLabels(t *testing.T) {
	for _, tc := range []struct {
		name       string
		assertions []finder.Assertion
		complete   bool
		want       string
	}{
		{"fixed row matching vulnerable image", []finder.Assertion{{Match: true, Fixed: "1.2.3"}}, true, "Affected"},
		{"not affected", []finder.Assertion{{Match: true, Invert: true}}, true, "Not affected"},
		{"conflict", []finder.Assertion{{Match: true}, {Match: true, Invert: true}}, true, "Conflicting evidence"},
		{"no match", []finder.Assertion{{Fixed: "1.2.3"}}, true, "No matching assertion"},
		{"parser incomplete", nil, false, "Incomplete"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := &finder.Report{Assertions: tc.assertions}
			if tc.complete {
				report.VulnerabilityReport = &claircore.VulnerabilityReport{}
			}
			if got := conclude(report).decision().Label; got != tc.want {
				t.Fatalf("decision = %q; want %q", got, tc.want)
			}
		})
	}
}

func TestHTMLCollapsesLongEvidenceLists(t *testing.T) {
	var trace strings.Builder
	trace.WriteString("Step 5 — Match OCI component names\n  New VEX feed: 11 of 11 components match the image name\n")
	for i := 0; i < 11; i++ {
		trace.WriteString("    MATCH: assertion\n")
	}
	trace.WriteString("  Old VEX feed: 1 of 1 components match the image name\n    MATCH: legacy assertion\n")
	var out bytes.Buffer
	if err := renderHTML(&out, options{cve: "CVE-2099-0001"}, trace.String()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `<details class="value-list evidence-group"><summary>Evidence records (11)</summary>`) ||
		!strings.Contains(out.String(), `<details class="value-list evidence-group"><summary>Evidence records (1)</summary>`) {
		t.Fatal("evidence sections should collapse together when either feed has a long list")
	}
}

func TestHTMLEvidenceSectionsAreConsistentAcrossFeeds(t *testing.T) {
	trace := "Step 5 — Match OCI component names\n" +
		"  Old VEX feed: 1 component matches\n    MATCH: old component\n" +
		"  New VEX feed: 0 components match\n"
	var out bytes.Buffer
	if err := renderHTML(&out, options{cve: "CVE-2099-0001"}, trace); err != nil {
		t.Fatal(err)
	}
	html := out.String()
	if !strings.Contains(html, `<details class="value-list evidence-group" open><summary>Evidence records (1)</summary>`) ||
		!strings.Contains(html, `<details class="value-list evidence-group" open><summary>Evidence records (0)</summary>`) ||
		!strings.Contains(html, `No detailed records to show.`) {
		t.Fatal("feed evidence sections have different structure or omit empty evidence")
	}
}

func TestHTMLRemovesTerminalAlignmentFromLayerValues(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"    Name:     openshift/base-rhel9", "openshift/base-rhel9"},
		{"    CPE:     cpe:/a:redhat:openshift:4.16::el9", "cpe:/a:redhat:openshift:4.16::el9"},
		{"    Skipped:  usr/share/buildinfo/labels.json", "usr/share/buildinfo/labels.json"},
	} {
		if got := formatLine(tc.input).Value; got != tc.want {
			t.Errorf("formatLine(%q).Value = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestHTMLShowsMatchedAssertionsAndCollapsesNonMatches(t *testing.T) {
	step := htmlStep{Number: 8, Lines: []htmlLine{
		formatLine("  New VEX feed: 1 of 3 assertions match this image"),
		formatLine("    SKIP: old assertion"),
		formatLine("      Fixed version: 1.2.3"),
		formatLine("    MATCH: current assertion"),
		formatLine("      Repository CPE: cpe:/o:example:current"),
		formatLine("    SKIP: unrelated assertion"),
		formatLine("      Repository CPE: cpe:/o:example:other"),
		formatLine("    Conclusion: Affected"),
	}}
	organizeStep(&step)
	feed := step.Feeds[0]
	if len(feed.Items) != 1 || feed.Items[0].Heading.Text != "current assertion" || feed.CollapseItems {
		t.Fatalf("matching assertion should be visible: %+v", feed)
	}
	if len(feed.Skipped) != 2 || feed.Skipped[0].Details[0].Value != "1.2.3" || feed.Skipped[1].Details[0].Value != "cpe:/o:example:other" {
		t.Fatalf("non-matching assertion details were lost: %+v", feed.Skipped)
	}
	if len(feed.After) != 1 || feed.After[0].Value != "Affected" {
		t.Fatalf("feed conclusion was misplaced: %+v", feed.After)
	}
	var out bytes.Buffer
	trace := "Step 8 — Check Claircore assertions\n  New VEX feed: 1 of 2 assertions match this image\n    MATCH: current assertion\n    SKIP: old assertion\n      Fixed version: 1.2.3\n    Conclusion: Affected\n"
	if err := renderHTML(&out, options{cve: "CVE-2099-0001"}, trace); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `<details class="value-list"><summary>Non-matching Claircore assertions (1)</summary>`) ||
		!strings.Contains(out.String(), `<details class="value-list evidence-group" open><summary>Evidence records (1)</summary>`) {
		t.Fatal("non-matching assertions are not collapsed by default")
	}
}

func TestHTMLGroupsEvidenceByFeedAndKeepsLayerDecisionAfterLayers(t *testing.T) {
	step := htmlStep{Number: 5, Lines: []htmlLine{
		formatLine("  Old VEX feed: 1 of 2 components match"),
		formatLine("    MATCH: old component"),
		formatLine("      PURL: pkg:oci/old"),
		formatLine("    Conclusion: old feed outcome"),
		formatLine("  New VEX feed: 0 of 2 components match"),
		formatLine("    SKIP: new component"),
		formatLine("      PURL: pkg:oci/new"),
	}}
	organizeStep(&step)
	if len(step.Feeds) != 2 || len(step.Feeds[0].Items) != 1 || len(step.Feeds[1].Items) != 1 {
		t.Fatalf("feed evidence was not separated: %+v", step.Feeds)
	}
	if step.Feeds[0].Items[0].Details[0].Value != "pkg:oci/old" || step.Feeds[1].Items[0].Details[0].Value != "pkg:oci/new" {
		t.Fatalf("evidence details were assigned to the wrong feed: %+v", step.Feeds)
	}
	if len(step.Feeds[0].After) != 1 || step.Feeds[0].After[0].Value != "old feed outcome" {
		t.Fatalf("feed conclusion did not follow the evidence: %+v", step.Feeds[0])
	}
	layers := htmlStep{Number: 2, Lines: []htmlLine{
		formatLine("  Layer 0 (old):"),
		formatLine("    Name: old"),
		formatLine("  Matching layer: 0 (latest with RHCC repository content)."),
	}}
	organizeStep(&layers)
	if len(layers.Blocks) != 1 || len(layers.Blocks[0].Lines) != 1 || len(layers.After) != 1 {
		t.Fatalf("layer decision did not follow the layer card: %+v", layers)
	}
}

func TestComparisonValuesIncludeRejectedDistinctCandidates(t *testing.T) {
	report := &finder.Report{
		Candidates: []finder.Candidate{
			{Derived: "example/widget", Match: true},
			{Derived: "example/other"},
			{Derived: "example/other"},
		},
		Products: []finder.ProductCheck{
			{CPE: "cpe:/o:example:widget", Match: true},
			{CPE: "cpe:/o:example:other"},
			{CPE: "cpe:/o:example:other"},
		},
	}
	var out bytes.Buffer
	printReports(&out, []documentReport{{name: "Old VEX feed", report: report}}, options{}, "example/widget", "cpe:/o:example:widget")
	for _, want := range []string{
		`Image name: "example/widget"`,
		"Component names found in VEX: 2 distinct",
		`Candidate name: "example/other" (SKIP)`,
		"Image CPE: cpe:/o:example:widget",
		"Product CPEs found in VEX: 2 distinct",
		"Advisory CPE: cpe:/o:example:other (SKIP)",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing compared value %q:\n%s", want, out.String())
		}
	}
}

func TestUnknownFormat(t *testing.T) {
	cmd := newCommand()
	cmd.SetArgs([]string{"--format", "pdf"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "unknown output format") {
		t.Fatalf("expected format error, got %v", err)
	}
}

func TestEmbedVEXDocsRequiresHTML(t *testing.T) {
	cmd := newCommand()
	cmd.SetArgs([]string{"--embed-vex-docs"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "requires --format html") {
		t.Fatalf("expected HTML-only flag error, got %v", err)
	}
}
