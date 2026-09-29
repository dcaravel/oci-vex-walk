package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
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

func TestCSVReportShowsFeedConclusionsForSpreadsheet(t *testing.T) {
	demo, err := os.ReadFile("../../testdata/demo.json")
	if err != nil {
		t.Fatal(err)
	}
	var input struct{ Labels, Document json.RawMessage }
	if err := json.Unmarshal(demo, &input); err != nil {
		t.Fatal(err)
	}
	manifest, _ := json.Marshal([]map[string]any{{"Layers": []string{"layer.tar"}}})
	archive := tarBytes(t, map[string][]byte{
		"manifest.json": manifest,
		"layer.tar":     tarBytes(t, map[string][]byte{"root/buildinfo/labels.json": input.Labels}),
	})
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "image,part.tar")
	oldPath := filepath.Join(dir, "old.json")
	newPath := filepath.Join(dir, "new.json")
	oldDocument := bytes.ReplaceAll(input.Document, []byte("example/widget"), []byte("example/other"))
	for path, data := range map[string][]byte{archivePath: archive, oldPath: oldDocument, newPath: input.Document} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	var out, progress bytes.Buffer
	cmd := newCommand()
	cmd.SetOut(&out)
	cmd.SetErr(&progress)
	cmd.SetArgs([]string{"--archive", archivePath, "--cve", "CVE-2099-0001", "--old-document", oldPath, "--new-document", newPath, "--format", "csv"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	records, err := csv.NewReader(&out).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("CSV has %d rows, want header and one result: %q", len(records), out.String())
	}
	wantHeader := []string{"image", "cve", "detected_name", "detected_cpe", "old_vex_conclusion", "new_vex_conclusion"}
	if !reflect.DeepEqual(records[0], wantHeader) {
		t.Fatalf("CSV header = %q", records[0])
	}
	row := records[1]
	if row[0] != archivePath || row[1] != "CVE-2099-0001" || row[2] != "example/widget" || row[3] != "cpe:/a:redhat:widget:4.13::el8" || row[4] != "No matching assertion — OCI name not found" || row[5] != "Conflicting evidence" {
		t.Fatalf("unexpected CSV row: %q", row)
	}
	if strings.Contains(out.String(), "Step 1") || strings.Contains(out.String(), "Step 9") {
		t.Fatalf("CSV contains walkthrough trace: %s", out.String())
	}
	var trace, page bytes.Buffer
	var summary walkSummary
	if err := run(context.Background(), options{archive: archivePath, cve: "CVE-2099-0001", oldDocument: oldPath, newDocument: newPath, summary: &summary}, &trace); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(trace.String(), "Conclusion: No matching assertion — OCI name not found") {
		t.Fatalf("text conclusion does not name the failed check: %s", trace.String())
	}
	if err := renderHTMLWithSummary(&page, options{archive: archivePath, cve: "CVE-2099-0001"}, summary, trace.String()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(page.String(), "<strong>No matching assertion — OCI name not found</strong>") {
		t.Fatal("HTML conclusion differs from text and CSV")
	}

	out.Reset()
	cmd = newCommand()
	cmd.SetOut(&out)
	cmd.SetErr(&progress)
	cmd.SetArgs([]string{"--archive", archivePath, "--cve", "CVE-2099-0001", "--old-document", filepath.Join(dir, "missing.json"), "--new-document", newPath, "--format", "csv"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	records, err = csv.NewReader(&out).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[1][4] != "Unavailable" || records[1][5] != "Conflicting evidence" {
		t.Fatalf("unavailable old feed CSV = %q", records)
	}
	out.Reset()
	cmd = newCommand()
	cmd.SetOut(&out)
	cmd.SetErr(&progress)
	cmd.SetArgs([]string{"--archive", archivePath, "--cve", "CVE-2099-0001", "--old-document", newPath, "--new-document", filepath.Join(dir, "missing.json"), "--format", "csv"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	records, err = csv.NewReader(&out).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[1][4] != "Conflicting evidence" || records[1][5] != "Unavailable" {
		t.Fatalf("unavailable new feed changed old conclusion: %q", records)
	}
	trace.Reset()
	page.Reset()
	summary = walkSummary{}
	if err := run(context.Background(), options{archive: archivePath, cve: "CVE-2099-0001", oldDocument: newPath, newDocument: filepath.Join(dir, "missing.json"), summary: &summary}, &trace); err != nil {
		t.Fatal(err)
	}
	var textReport bytes.Buffer
	if err := renderText(&textReport, summary, trace.String()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(textReport.String(), "Conclusion (New VEX feed): Unavailable") || !strings.Contains(textReport.String(), "Old VEX feed: Conflicting evidence") {
		t.Fatal("text feed conclusions are not independent")
	}
	if err := renderHTMLWithSummary(&page, options{archive: archivePath, cve: "CVE-2099-0001"}, summary, trace.String()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(page.String(), `<div class="decision-card unknown" data-feed="new"><p class="decision-source">New VEX feed · Claircore source</p><strong>Unavailable</strong>`) || !strings.Contains(page.String(), `<strong>Conflicting evidence</strong>`) {
		t.Fatal("HTML feed conclusions are not independent")
	}

	invalidPath := filepath.Join(dir, "invalid.json")
	if err := os.WriteFile(invalidPath, []byte("{invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	cmd = newCommand()
	cmd.SetOut(&out)
	cmd.SetErr(&progress)
	cmd.SetArgs([]string{"--archive", archivePath, "--cve", "CVE-2099-0001", "--old-document", invalidPath, "--new-document", newPath, "--format", "csv"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	records, err = csv.NewReader(&out).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[1][4] != "Incomplete" || records[1][5] != "Conflicting evidence" {
		t.Fatalf("invalid old feed changed new conclusion: %q", records)
	}

	cpePath := filepath.Join(dir, "cpe-mismatch.json")
	cpeDocument := bytes.ReplaceAll(input.Document, []byte("cpe:/a:redhat:widget:4"), []byte("cpe:/a:redhat:other:4"))
	if err := os.WriteFile(cpePath, cpeDocument, 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	cmd = newCommand()
	cmd.SetOut(&out)
	cmd.SetErr(&progress)
	cmd.SetArgs([]string{"--archive", archivePath, "--cve", "CVE-2099-0001", "--old-document", cpePath, "--new-document", newPath, "--format", "csv"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	records, err = csv.NewReader(&out).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if got := records[1][4]; got != "No matching assertion — product CPE not found" {
		t.Fatalf("CPE mismatch conclusion = %q", got)
	}
}

func TestNoRHCCIdentityMarksBothFeedsIncomplete(t *testing.T) {
	manifest, _ := json.Marshal([]map[string]any{{"Layers": []string{"layer.tar"}}})
	archive := tarBytes(t, map[string][]byte{
		"manifest.json": manifest,
		"layer.tar":     tarBytes(t, map[string][]byte{"unrelated.txt": []byte("no buildinfo")}),
	})
	archivePath := filepath.Join(t.TempDir(), "image.tar")
	if err := os.WriteFile(archivePath, archive, 0600); err != nil {
		t.Fatal(err)
	}
	var summary walkSummary
	if err := run(context.Background(), options{archive: archivePath, cve: "CVE-2099-0001", summary: &summary}, io.Discard); err != nil {
		t.Fatal(err)
	}
	if summary.legacyDecision().Label != "Incomplete" || summary.currentDecision().Label != "Incomplete" {
		t.Fatalf("no image identity decisions = old %q, new %q", summary.legacyDecision().Label, summary.currentDecision().Label)
	}
}

func TestStepTwoStopExplainsLabelsFailureInTextHTMLAndCSV(t *testing.T) {
	demo, err := os.ReadFile("../../testdata/demo.json")
	if err != nil {
		t.Fatal(err)
	}
	var input struct{ Labels json.RawMessage }
	if err := json.Unmarshal(demo, &input); err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(input.Labels, &fields); err != nil {
		t.Fatal(err)
	}
	delete(fields, "org.opencontainers.image.created")
	missingCreated, _ := json.Marshal(fields)
	for _, tc := range []struct {
		name, label, detail string
		layers              [][]byte
	}{
		{"missing created after older valid identity", "Incomplete — labels.json missing created", "older identities are unmatchable", [][]byte{input.Labels, missingCreated}},
		{"invalid labels JSON", "Incomplete — invalid labels.json", "invalid JSON", [][]byte{[]byte("{bad")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var layerPaths []string
			files := map[string][]byte{}
			for i, labels := range tc.layers {
				path := fmt.Sprintf("layer-%d.tar", i)
				layerPaths = append(layerPaths, path)
				files[path] = tarBytes(t, map[string][]byte{"root/buildinfo/labels.json": labels})
			}
			files["manifest.json"], _ = json.Marshal([]map[string]any{{"Layers": layerPaths}})
			archivePath := filepath.Join(t.TempDir(), "image.tar")
			if err := os.WriteFile(archivePath, tarBytes(t, files), 0600); err != nil {
				t.Fatal(err)
			}
			var trace, page, csvOutput bytes.Buffer
			var summary walkSummary
			o := options{archive: archivePath, cve: "CVE-2099-0001", summary: &summary}
			if err := run(context.Background(), o, &trace); err != nil {
				t.Fatal(err)
			}
			if summary.Current.Label != tc.label || summary.Legacy.Label != tc.label {
				t.Fatalf("conclusions = old %q, new %q", summary.Legacy.Label, summary.Current.Label)
			}
			if !strings.Contains(trace.String(), "Stop reason:") || !strings.Contains(trace.String(), tc.detail) || strings.Contains(trace.String(), "Step 3 —") {
				t.Fatalf("step 2 did not explain stop: %s", trace.String())
			}
			if err := renderHTMLWithSummary(&page, o, summary, trace.String()); err != nil {
				t.Fatal(err)
			}
			if strings.Count(page.String(), "<strong>"+tc.label+"</strong>") != 2 || !strings.Contains(page.String(), tc.detail) {
				t.Fatalf("HTML verdict omitted stop cause: %s", page.String())
			}
			if err := renderCSV(&csvOutput, o, summary); err != nil {
				t.Fatal(err)
			}
			records, err := csv.NewReader(&csvOutput).ReadAll()
			if err != nil {
				t.Fatal(err)
			}
			if len(records) != 2 || records[1][4] != tc.label || records[1][5] != tc.label {
				t.Fatalf("CSV conclusions omitted stop cause: %q", records)
			}
			if tc.name == "missing created after older valid identity" {
				inputPath := filepath.Join(t.TempDir(), "input.csv")
				if err := os.WriteFile(inputPath, []byte("image,cve\ndocker-archive:"+archivePath+",CVE-2099-0001\n"), 0600); err != nil {
					t.Fatal(err)
				}
				var batchOutput bytes.Buffer
				cmd := newCommand()
				cmd.SetOut(&batchOutput)
				cmd.SetErr(io.Discard)
				cmd.SetArgs([]string{"--input-csv", inputPath})
				if err := cmd.Execute(); err != nil {
					t.Fatal(err)
				}
				batchRecords, err := csv.NewReader(&batchOutput).ReadAll()
				if err != nil {
					t.Fatal(err)
				}
				if len(batchRecords) != 2 || batchRecords[1][4] != tc.label || batchRecords[1][5] != tc.label {
					t.Fatalf("batch CSV conclusions omitted stop cause: %q", batchRecords)
				}
			}
		})
	}
}

func TestNoMatchConclusionIdentifiesFailedStage(t *testing.T) {
	const feed = "Old VEX feed"
	base := feedConclusion{complete: true}
	for _, tc := range []struct {
		name   string
		counts feedConclusion
		report *finder.Report
		want   string
	}{
		{"name", base, &finder.Report{}, "No matching assertion — OCI name not found"},
		{"legacy names", base, &finder.Report{GoldRepo: true, ImageNames: []string{"example/source", "example/repo-a", "example/repo-b"}}, "No matching assertion — no eligible package name found"},
		{"CPE", feedConclusion{complete: true, components: 1}, &finder.Report{}, "No matching assertion — product CPE not found"},
		{"GoldRepo product", feedConclusion{complete: true, components: 1}, &finder.Report{GoldRepo: true}, "No matching assertion — advisory product not found"},
		{"relationship", feedConclusion{complete: true, components: 1, products: 1}, &finder.Report{}, "No matching assertion — name/CPE not linked"},
		{"GoldRepo relationship", feedConclusion{complete: true, components: 1, products: 1}, &finder.Report{GoldRepo: true}, "No matching assertion — name/product not linked"},
		{"linked status", feedConclusion{complete: true, components: 1, products: 1, statuses: 1}, &finder.Report{}, "No matching assertion — linked status, no assertion"},
		{"assertion CPE", feedConclusion{complete: true, components: 1, products: 1, statuses: 1}, &finder.Report{Assertions: []finder.Assertion{{Steps: []finder.Step{{Title: "Standard CPE comparison", Result: "Advisory is a superset of, or equal to, image: false"}, {Title: "Red Hat prefix fallback", Result: "Image CPE starts with trimmed advisory CPE: false"}, {Title: "Database version-range filter", Result: "Image normalized version in [lower, upper): true"}}}}}, "No matching assertion — assertion CPE mismatch"},
		{"version range", feedConclusion{complete: true, components: 1, products: 1, statuses: 1}, &finder.Report{Assertions: []finder.Assertion{{Steps: []finder.Step{{Title: "Standard CPE comparison", Result: "Advisory is a superset of, or equal to, image: true"}, {Title: "Database version-range filter", Result: "Image normalized version in [lower, upper): false"}}}}}, "No matching assertion — version outside range"},
		{"fixed version", feedConclusion{complete: true, components: 1, products: 1, statuses: 1}, &finder.Report{Assertions: []finder.Assertion{{Fixed: "1.2.3", Steps: []finder.Step{{Title: "Standard CPE comparison", Result: "Advisory is a superset of, or equal to, image: true"}, {Title: "Database version-range filter", Result: "Image normalized version in [lower, upper): true"}, {Title: "RHCC matcher", Result: "Compare image version with fixed version using RPM EVR ordering. Match: false"}}}}}, "No matching assertion — fixed-version check"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := explainNoMatch(tc.counts, []documentReport{{name: feed, report: tc.report}}, feed)
			if got.Label != tc.want || !strings.Contains(got.Reason, "does not establish") {
				t.Fatalf("decision = %+v, want %q with scope caveat", got, tc.want)
			}
			if tc.name == "legacy names" && !strings.Contains(got.Reason, "example/repo-a; example/repo-b; example/source") {
				t.Fatalf("legacy no-match reason omitted checked package names: %q", got.Reason)
			}
		})
	}
}

func TestLinkedKnownAffectedBinaryNameDoesNotMatchLegacySourcePackage(t *testing.T) {
	demo, err := os.ReadFile("../../testdata/demo.json")
	if err != nil {
		t.Fatal(err)
	}
	var input struct{ Document json.RawMessage }
	if err := json.Unmarshal(demo, &input); err != nil {
		t.Fatal(err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(input.Document, &document); err != nil {
		t.Fatal(err)
	}
	var vulnerabilities []map[string]json.RawMessage
	if err := json.Unmarshal(document["vulnerabilities"], &vulnerabilities); err != nil {
		t.Fatal(err)
	}
	var statuses map[string]json.RawMessage
	if err := json.Unmarshal(vulnerabilities[0]["product_status"], &statuses); err != nil {
		t.Fatal(err)
	}
	statuses["known_affected"] = statuses["fixed"]
	delete(statuses, "fixed")
	delete(statuses, "known_not_affected")
	vulnerabilities[0]["product_status"], _ = json.Marshal(statuses)
	document["vulnerabilities"], _ = json.Marshal(vulnerabilities)
	data, _ := json.Marshal(document)
	legacy := &finder.LegacyIdentity{Path: "root/buildinfo/Dockerfile-example", Name: "example/legacy", Component: "example/source", Architecture: "x86_64", Version: "v4.13.0-1", Repositories: []string{"example/widget"}}
	report, err := finder.Analyze(finder.Request{CVE: "CVE-2099-0001", Document: string(data), Legacy: legacy})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Statuses) == 0 || !report.Statuses[0].Relevant || len(report.Assertions) != 0 {
		t.Fatalf("expected linked status but no source-package assertion: %+v", report)
	}
	var trace, page, csvOutput bytes.Buffer
	var summary walkSummary
	o := options{cve: "CVE-2099-0001", summary: &summary}
	printReports(&trace, []documentReport{{name: "New VEX feed", identity: "legacy Dockerfile", report: report}}, o, "example/source; example/widget", "")
	if summary.Current.Label != "No matching assertion — source package name mismatch" ||
		!strings.Contains(summary.Current.Reason, "example/widget") || !strings.Contains(summary.Current.Reason, "example/source") ||
		!strings.Contains(trace.String(), "Source package check:") || !strings.Contains(trace.String(), "Step 8 —") {
		t.Fatalf("trace did not explain package kind mismatch: %+v\n%s", summary.Current, trace.String())
	}
	if err := renderHTMLWithSummary(&page, o, summary, trace.String()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(page.String(), "Source package check") || !strings.Contains(page.String(), "source package name mismatch") {
		t.Fatal("HTML report omitted package kind mismatch")
	}
	if err := renderCSV(&csvOutput, o, summary); err != nil {
		t.Fatal(err)
	}
	records, err := csv.NewReader(&csvOutput).ReadAll()
	if err != nil || len(records) != 2 || records[1][5] != summary.Current.Label {
		t.Fatalf("CSV omitted package kind mismatch: %q, %v", records, err)
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
	if len(captured) != 3 || captured[0].Filename != "container-name-repos-map.json" || summary.Current.Label != "Conflicting evidence" || summary.DetectedName != "example-source-container; example/widget" {
		t.Fatalf("legacy source capture or combined conclusion missing: %d captures, current %q", len(captured), summary.Current.Label)
	}
	var csvOutput bytes.Buffer
	if err := renderCSV(&csvOutput, options{archive: archivePath, cve: "CVE-2099-0001"}, summary); err != nil {
		t.Fatal(err)
	}
	records, err := csv.NewReader(&csvOutput).ReadAll()
	if err != nil || len(records) != 2 || records[1][2] != "example-source-container; example/widget" || records[1][3] != "" {
		t.Fatalf("legacy CSV should contain resolved package names and no CPE: %q, %v", records, err)
	}
	inputPath := filepath.Join(dir, "input.csv")
	if err := os.WriteFile(inputPath, []byte("image,cve\ndocker-archive:"+archivePath+",CVE-2099-0001\n"), 0600); err != nil {
		t.Fatal(err)
	}
	csvOutput.Reset()
	cmd := newCommand()
	cmd.SetOut(&csvOutput)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"--input-csv", inputPath, "--old-document", docPath, "--new-document", docPath, "--name-to-repos-map", mapPath})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	records, err = csv.NewReader(&csvOutput).ReadAll()
	if err != nil || len(records) != 2 || records[1][2] != "example-source-container; example/widget" || records[1][3] != "" {
		t.Fatalf("batch CSV should contain resolved package names and no CPE: %q, %v", records, err)
	}
	unmatchedPath := filepath.Join(dir, "unmatched.json")
	unmatched := bytes.ReplaceAll(input.Document, []byte("example/widget"), []byte("example/unmatched"))
	unmatched = bytes.ReplaceAll(unmatched, []byte("example-source-container"), []byte("example/unmatched-source"))
	if err := os.WriteFile(unmatchedPath, unmatched, 0600); err != nil {
		t.Fatal(err)
	}
	csvOutput.Reset()
	cmd = newCommand()
	cmd.SetOut(&csvOutput)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"--input-csv", inputPath, "--old-document", unmatchedPath, "--new-document", docPath, "--name-to-repos-map", mapPath})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	records, err = csv.NewReader(&csvOutput).ReadAll()
	if err != nil || len(records) != 2 || records[1][4] != "No matching assertion — no eligible package name found" || records[1][5] != "Conflicting evidence" {
		t.Fatalf("batch CSV should distinguish legacy name failure by feed: %q, %v", records, err)
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
	if summary.Current.Label != "Conflicting evidence" || summary.DetectedName != "example-source-container; example/widget" ||
		!strings.Contains(trace.String(), "Identity: labels.json: 1 affected, 1 not affected") ||
		!strings.Contains(trace.String(), "Identity: legacy Dockerfile: 1 affected, 1 not affected") ||
		!strings.Contains(trace.String(), "Matched assertions: 2 affected, 2 not affected") {
		t.Fatal("combined report did not preserve both eligible Claircore identities")
	}
	if err := os.WriteFile(mapPath, []byte(`{"data":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	trace.Reset()
	summary = walkSummary{}
	if err := run(context.Background(), options{archive: archivePath, cve: "CVE-2099-0001", oldDocument: docPath, newDocument: docPath, nameToReposMap: mapPath, summary: &summary}, &trace); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(trace.String(), "Map entry: absent; Claircore uses the name label") ||
		!strings.Contains(trace.String(), "Identity: legacy Dockerfile: 0 affected, 0 not affected") ||
		summary.DetectedName != "example-source-container; example/legacy; example/widget" {
		t.Fatal("missing map entry did not fall back to the Dockerfile name label")
	}
}

func TestAffectedLegacyIdentityIsVisibleBeforeAndAfterDetailedSteps(t *testing.T) {
	demo, err := os.ReadFile("../../testdata/demo.json")
	if err != nil {
		t.Fatal(err)
	}
	var input struct{ Labels, Document json.RawMessage }
	if err := json.Unmarshal(demo, &input); err != nil {
		t.Fatal(err)
	}
	var labels map[string]any
	if err := json.Unmarshal(input.Labels, &labels); err != nil {
		t.Fatal(err)
	}
	labels["name"] = "example/unrelated"
	unrelatedLabels, _ := json.Marshal(labels)
	var document map[string]json.RawMessage
	if err := json.Unmarshal(input.Document, &document); err != nil {
		t.Fatal(err)
	}
	var vulnerabilities []map[string]json.RawMessage
	if err := json.Unmarshal(document["vulnerabilities"], &vulnerabilities); err != nil {
		t.Fatal(err)
	}
	var statuses map[string]json.RawMessage
	if err := json.Unmarshal(vulnerabilities[0]["product_status"], &statuses); err != nil {
		t.Fatal(err)
	}
	delete(statuses, "known_not_affected")
	vulnerabilities[0]["product_status"], _ = json.Marshal(statuses)
	document["vulnerabilities"], _ = json.Marshal(vulnerabilities)
	newDocument, _ := json.Marshal(document)
	manifest, _ := json.Marshal([]map[string]any{{"Layers": []string{"layer.tar"}}})
	archive := tarBytes(t, map[string][]byte{
		"manifest.json": manifest,
		"layer.tar": tarBytes(t, map[string][]byte{
			"root/buildinfo/labels.json":                         unrelatedLabels,
			"root/buildinfo/Dockerfile-example-legacy-v4.13.0-1": []byte("FROM scratch\nLABEL name=\"example/legacy\"\nLABEL com.redhat.component=\"example-source-container\"\nLABEL architecture=\"x86_64\"\n"),
		}),
	})
	dir := t.TempDir()
	archivePath, docPath, mapPath := filepath.Join(dir, "image.tar"), filepath.Join(dir, "vex.json"), filepath.Join(dir, "map.json")
	for path, data := range map[string][]byte{
		archivePath: archive,
		docPath:     newDocument,
		mapPath:     []byte(`{"data":{"example/legacy":["example/widget"]}}`),
	} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	var trace, page bytes.Buffer
	var summary walkSummary
	o := options{archive: archivePath, cve: "CVE-2099-0001", oldDocument: docPath, newDocument: docPath, nameToReposMap: mapPath, summary: &summary}
	if err := run(context.Background(), o, &trace); err != nil {
		t.Fatal(err)
	}
	if summary.Current.Label != "Affected" || !strings.Contains(summary.Current.Reason, "legacy Dockerfile (GoldRepo; advisory CPE not compared)") || !strings.Contains(summary.Current.Reason, "fixed version") || !strings.Contains(summary.Current.Reason, "CSAF status") {
		t.Fatalf("new feed verdict lacks matching identity: %+v\n%s", summary.Current, trace.String())
	}
	if summary.DetectedName != "example-source-container; example/unrelated; example/widget" {
		t.Fatalf("detected names should include labels and resolved legacy package names, got %q", summary.DetectedName)
	}
	var csvOutput bytes.Buffer
	if err := renderCSV(&csvOutput, o, summary); err != nil {
		t.Fatal(err)
	}
	records, err := csv.NewReader(&csvOutput).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[1][2] != summary.DetectedName {
		t.Fatalf("CSV lost matching package names: %q", records)
	}
	for _, want := range []string{"Step 7 —", "Step 8 —", "Step 9 —", "Image name: \"example/unrelated\" (from this labels.json identity)", "Names eligible for GoldRepo matching: example-source-container, example/widget", "GoldRepo: advisory CPE is not compared", "Identity: labels.json: 0 affected", "Identity: legacy Dockerfile: 1 affected"} {
		if !strings.Contains(trace.String(), want) {
			t.Errorf("trace omitted %q", want)
		}
	}
	if err := renderHTMLWithSummary(&page, o, summary, trace.String()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`id="step-7"`, `id="step-8"`, `id="step-9"`, `href="#step-8">Matched assertions</a>`, `legacy Dockerfile (GoldRepo; advisory CPE not compared)`, `<p class="feed-identity">Identity: <code class="entry-code">legacy Dockerfile</code></p>`} {
		if !strings.Contains(page.String(), want) {
			t.Errorf("HTML omitted %q", want)
		}
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
	if strings.Count(out.String(), `<strong>Incomplete</strong>`) != 2 {
		t.Fatal("partial walkthrough should mark both feeds incomplete")
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
	large := htmlStep{Number: 8, Lines: []htmlLine{formatLine("  New VEX feed: 11 of 11 assertions match this image")}}
	for i := 0; i < 11; i++ {
		large.Lines = append(large.Lines, formatLine(fmt.Sprintf("    MATCH: assertion %d", i)))
	}
	organizeStep(&large)
	if len(large.Feeds) != 1 || !large.Feeds[0].CollapseItems {
		t.Fatal("large matched assertion lists should start collapsed")
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
		Identity:   "labels.json",
		ImageNames: []string{"example/widget"},
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
