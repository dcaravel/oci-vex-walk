package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestBatchCSVPreservesRowsAndReusesImagesAndDocuments(t *testing.T) {
	demo, err := os.ReadFile("../../testdata/demo.json")
	if err != nil {
		t.Fatal(err)
	}
	var input struct{ Labels, Document json.RawMessage }
	if err := json.Unmarshal(demo, &input); err != nil {
		t.Fatal(err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(input.Document, &document); err != nil {
		t.Fatal(err)
	}
	var vulnerabilities []json.RawMessage
	if err := json.Unmarshal(document["vulnerabilities"], &vulnerabilities); err != nil {
		t.Fatal(err)
	}
	second := bytes.ReplaceAll(vulnerabilities[0], []byte("CVE-2099-0001"), []byte("CVE-2099-0002"))
	document["vulnerabilities"], _ = json.Marshal(append(vulnerabilities, second))
	multiCVE, _ := json.Marshal(document)
	var fetches atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		_, _ = w.Write(multiCVE)
	}))
	defer server.Close()

	manifest, _ := json.Marshal([]map[string]any{{"Layers": []string{"layer.tar"}}})
	archive := tarBytes(t, map[string][]byte{
		"manifest.json": manifest,
		"layer.tar":     tarBytes(t, map[string][]byte{"root/buildinfo/labels.json": input.Labels}),
	})
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "fixture.tar")
	if err := os.WriteFile(archivePath, archive, 0600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "pulls.log")
	script := "#!/bin/sh\nfor arg do target=\"$arg\"; done\nprintf 'pull\\n' >> \"$OCIVEX_TEST_PULL_LOG\"\ncp \"$OCIVEX_TEST_ARCHIVE\" \"${target#docker-archive:}\"\n"
	if err := os.WriteFile(filepath.Join(dir, "skopeo"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("OCIVEX_TEST_ARCHIVE", archivePath)
	t.Setenv("OCIVEX_TEST_PULL_LOG", logPath)
	inputPath := filepath.Join(dir, "input.csv")
	data := "Asset,Finding,Note,detected_name\nregistry.example/a:1,CVE-2099-0001,first,stale\nregistry.example/b:1,CVE-2099-0001,other image,stale\nregistry.example/a:1,CVE-2099-0002,other CVE,stale\nregistry.example/a:1,CVE-2099-0001,repeat,stale\n"
	if err := os.WriteFile(inputPath, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	var out, progress bytes.Buffer
	cmd := newCommand()
	cmd.SetOut(&out)
	cmd.SetErr(&progress)
	cmd.SetArgs([]string{"--input-csv", inputPath, "--image-column", "A", "--cve-column", "B", "--old-document", server.URL, "--new-document", server.URL})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	records, err := csv.NewReader(&out).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 5 || len(records[0]) != 8 {
		t.Fatalf("unexpected CSV shape: %q", records)
	}
	if records[0][0] != "Asset" || records[0][2] != "Note" || records[0][3] != "detected_name" || records[0][6] != "new_vex_conclusion" || records[0][7] != "processing_error" {
		t.Fatalf("unexpected CSV header: %q", records[0])
	}
	for i, row := range records[1:] {
		if row[3] != "example/widget" || row[4] != "cpe:/a:redhat:widget:4.13::el8" || row[5] != "Conflicting evidence" || row[6] != "Conflicting evidence" || row[7] != "" {
			t.Fatalf("record %d has unexpected result: %q", i+2, row)
		}
	}
	if records[1][2] != "first" || records[2][2] != "other image" || records[3][2] != "other CVE" || records[4][2] != "repeat" {
		t.Fatalf("input fields changed: %q", records)
	}
	log, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if pulls := strings.Count(string(log), "pull\n"); pulls != 2 {
		t.Fatalf("skopeo pulled %d times, want once per image", pulls)
	}
	if got := fetches.Load(); got != 1 {
		t.Fatalf("VEX document fetched %d times, want once per source", got)
	}
	if runs := strings.Count(progress.String(), "Reading image layers"); runs != 3 {
		t.Fatalf("image analyzed %d times, want once per distinct image/CVE", runs)
	}
	for _, want := range []string{
		"Images processed: 0/2\n",
		"Images processed: 1/2\n",
		"Images processed: 2/2\n",
	} {
		if !strings.Contains(progress.String(), want) {
			t.Fatalf("missing batch progress %q in:\n%s", want, progress.String())
		}
	}
	if got := strings.Count(progress.String(), "Images processed: 2/2\n"); got != 1 {
		t.Fatalf("completion reported %d times, want once", got)
	}
}

func TestBatchCSVRejectsMissingColumnBeforePull(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "input.csv")
	if err := os.WriteFile(inputPath, []byte("image,cve\nexample/a,CVE-2099-0001\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	cmd := newCommand()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--input-csv", inputPath, "--image-column", "Missing"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "header \"Missing\" not found") {
		t.Fatalf("missing header error = %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("wrote partial CSV: %q", out.String())
	}
}

func TestBatchCSVContinuesAfterPullFailureAndFlushesRows(t *testing.T) {
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
	archivePath := filepath.Join(dir, "fixture.tar")
	docPath := filepath.Join(dir, "vex.json")
	inputPath := filepath.Join(dir, "input.csv")
	outputPath := filepath.Join(dir, "output.csv")
	logPath := filepath.Join(dir, "pulls.log")
	for path, data := range map[string][]byte{
		archivePath: archive,
		docPath:     input.Document,
		inputPath:   []byte("image,cve\nquay.local/dockerhub/bad:1,CVE-2099-0001\nquay.local/dockerhub/bad:1,CVE-2099-0001\nregistry.example/good:1,CVE-2099-0001\n"),
	} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	script := `#!/bin/sh
for arg do
  case "$arg" in
    docker://*) source="$arg" ;;
    docker-archive:*) target="$arg" ;;
  esac
done
printf 'pull\n' >> "$OCIVEX_TEST_PULL_LOG"
if [ "$source" = 'docker://quay.local/dockerhub/bad:1' ]; then
  grep -q 'processing_error' "$OCIVEX_TEST_OUTPUT" || exit 97
  echo 'lookup quay.local: no such host' >&2
  exit 1
fi
grep -q 'lookup quay.local: no such host' "$OCIVEX_TEST_OUTPUT" || exit 98
cp "$OCIVEX_TEST_ARCHIVE" "${target#docker-archive:}"
`
	if err := os.WriteFile(filepath.Join(dir, "skopeo"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("OCIVEX_TEST_ARCHIVE", archivePath)
	t.Setenv("OCIVEX_TEST_PULL_LOG", logPath)
	t.Setenv("OCIVEX_TEST_OUTPUT", outputPath)
	output, err := os.Create(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	var progress bytes.Buffer
	cmd := newCommand()
	cmd.SetOut(output)
	cmd.SetErr(&progress)
	cmd.SetArgs([]string{"--input-csv", inputPath, "--old-document", docPath, "--new-document", docPath})
	runErr := cmd.Execute()
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	if runErr == nil || !strings.Contains(runErr.Error(), "2 of 3 CSV records failed") {
		t.Fatalf("batch error = %v; progress:\n%s", runErr, progress.String())
	}
	f, err := os.Open(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	records, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 4 || records[0][6] != "processing_error" {
		t.Fatalf("unexpected partial output: %q", records)
	}
	for _, row := range records[1:3] {
		if row[4] != "" || row[5] != "" || !strings.Contains(row[6], "lookup quay.local: no such host") {
			t.Fatalf("failed row lacks error: %q", row)
		}
	}
	if records[3][4] != "Conflicting evidence" || records[3][5] != "Conflicting evidence" || records[3][6] != "" {
		t.Fatalf("later image was not processed: %q", records[3])
	}
	log, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if pulls := strings.Count(string(log), "pull\n"); pulls != 2 {
		t.Fatalf("skopeo pulled %d times, want one failed and one successful image", pulls)
	}
	if !strings.Contains(progress.String(), "Images processed: 2/2\n") {
		t.Fatalf("batch progress did not finish:\n%s", progress.String())
	}
}
