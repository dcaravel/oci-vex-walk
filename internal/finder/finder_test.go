package finder

import (
	"encoding/json"
	"github.com/quay/claircore/toolkit/types/cpe"
	"os"
	"strings"
	"testing"
)

func demo(t *testing.T) Request {
	t.Helper()
	b, e := os.ReadFile("../../testdata/demo.json")
	if e != nil {
		t.Fatal(e)
	}
	var x struct {
		CVE      string
		Labels   json.RawMessage
		Document json.RawMessage
	}
	if e = json.Unmarshal(b, &x); e != nil {
		t.Fatal(e)
	}
	return Request{CVE: x.CVE, Labels: string(x.Labels), Document: string(x.Document)}
}
func TestNameFallbacks(t *testing.T) {
	for _, tc := range []struct {
		purl, want string
		match      bool
	}{
		{"pkg:oci/example/widget?repository_url=registry/ignored", "example/widget", true},
		{"pkg:oci/widget?repository_url=registry/example/widget", "example/widget", true},
		{"pkg:oci/widget", "widget", true},
		{"pkg:oci/widget?repository_url=noslash", "widget", false},
		{"pkg:oci/widget?repository_url=registry/example%2Fwidget", "example/widget", true},
		{"not a purl", "widget", false},
	} {
		t.Run(tc.purl, func(t *testing.T) {
			got := derive(tc.purl, tc.want, "x86_64")
			if got.Match != tc.match {
				t.Fatalf("%+v", got)
			}
		})
	}
}
func TestCPEFallback(t *testing.T) {
	image, e := cpe.Unbind("cpe:/a:redhat:widget:4.13::el8")
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		s    string
		want bool
	}{{"cpe:/a:redhat:widget:4", true}, {"cpe:/a:redhat:widget:4.13::el8", true}, {"cpe:/a:redhat:other:4", false}, {"bad", false}} {
		got, _ := compareCPE(tc.s, image)
		if got != tc.want {
			t.Errorf("%s = %t", tc.s, got)
		}
	}
}
func TestEndToEndConflictingAssertions(t *testing.T) {
	report, e := Analyze(demo(t))
	if e != nil {
		t.Fatal(e)
	}
	affected, unaffected := 0, 0
	for _, a := range report.Assertions {
		if a.Match {
			if a.Invert {
				unaffected++
			} else {
				affected++
			}
		}
	}
	if affected != 1 || unaffected != 1 {
		b, _ := json.MarshalIndent(report, "", "  ")
		t.Fatalf("want both assertion types, got %d/%d: %s", affected, unaffected, b)
	}
	if got := report.VulnerabilityReport.PackageNotVulnerable["image-ancestry"]; len(got) != 1 {
		t.Fatalf("report preview missing inverted assertion: %v", got)
	}
	if got := report.VulnerabilityReport.PackageVulnerabilities["image-binary"]; len(got) != 1 {
		t.Fatalf("report preview missing affected assertion: %v", got)
	}
}

func TestLegacyGoldRepoMatchesMappedPackageAndBypassesCPE(t *testing.T) {
	req := demo(t)
	req.Labels = ""
	req.Legacy = &LegacyIdentity{
		Path: "root/buildinfo/Dockerfile-example-legacy-v4.13.0-1", Name: "example/legacy",
		Component: "example-source-container", Architecture: "x86_64", Version: "v4.13.0-1",
		Repositories: []string{"example/widget"},
	}
	report, err := Analyze(req)
	if err != nil {
		t.Fatal(err)
	}
	if !report.GoldRepo || report.VulnerabilityReport == nil {
		t.Fatal("legacy analysis did not create GoldRepo report evidence")
	}
	if got := len(report.VulnerabilityReport.PackageNotVulnerable["image-ancestry"]); got != 1 {
		t.Fatalf("mapped ancestry package did not surface the not-affected assertion: %d", got)
	}
	for _, product := range report.Products {
		if !product.Match {
			t.Fatalf("GoldRepo should not reject advisory CPE %q", product.CPE)
		}
	}
	req.Legacy.Repositories = []string{"example/unrelated"}
	report, err = Analyze(req)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.VulnerabilityReport.PackageNotVulnerable) != 0 || len(report.VulnerabilityReport.PackageVulnerabilities) != 0 {
		t.Fatal("unmapped package name must not surface VEX assertions")
	}
	req.Document = strings.Replace(req.Document, `"fixed": [`, `"known_affected": [`, 1)
	req.Legacy.Component = "example/widget"
	req.Legacy.Repositories = nil // A present but empty map entry emits only the source package.
	report, err = Analyze(req)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(report.VulnerabilityReport.PackageVulnerabilities["image-source"]); got != 1 {
		t.Fatalf("legacy source package did not surface known_affected assertion: %d", got)
	}
}
func TestFixedVersion(t *testing.T) {
	req := demo(t)
	req.Labels = strings.Replace(req.Labels, "2025-04-14T02:14:26Z", "2025-05-14T02:14:26Z", 1)
	r, e := Analyze(req)
	if e != nil {
		t.Fatal(e)
	}
	for _, a := range r.Assertions {
		if !a.Invert && a.Match {
			t.Fatal("newer image must not match fixed assertion")
		}
	}
}
func TestInvalidInputs(t *testing.T) {
	for _, change := range []func(*Request){func(r *Request) { r.CVE = "wrong" }, func(r *Request) { r.CVE = "CVE-2099-9999" }, func(r *Request) { r.Labels = `{}` }, func(r *Request) { r.Document = `{}` }, func(r *Request) { r.Labels = strings.Replace(r.Labels, "cpe:/a:redhat:widget:4.13::el8", "bad", 1) }} {
		r := demo(t)
		change(&r)
		if _, e := Analyze(r); e == nil {
			t.Fatal("expected validation error")
		}
	}
}
func TestNoMatchIsNotSafe(t *testing.T) {
	r := demo(t)
	r.Labels = strings.Replace(r.Labels, "example/widget", "example/unknown", 1)
	got, e := Analyze(r)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(got.Summary, "does not establish") {
		t.Fatal(got.Summary)
	}
}
func TestExtraQuotedLabels(t *testing.T) {
	r := demo(t)
	var x map[string]any
	json.Unmarshal([]byte(r.Labels), &x)
	x["name"] = `"example/widget"`
	b, _ := json.Marshal(x)
	r.Labels = string(b)
	got, e := Analyze(r)
	if e != nil {
		t.Fatal(e)
	}
	if len(got.Assertions) != 2 {
		t.Fatal("quoted name was not normalized")
	}
}
func TestNestedAndMissingRelationships(t *testing.T) {
	r := demo(t)
	var x map[string]any
	json.Unmarshal([]byte(r.Document), &x)
	tree := x["product_tree"].(map[string]any)
	rels := tree["relationships"].([]any)
	rels[0].(map[string]any)["product_reference"] = "nested"
	tree["relationships"] = append(rels, map[string]any{"category": "default_component_of", "full_product_name": map[string]any{"product_id": "nested", "name": "nested"}, "product_reference": "oci-repository", "relates_to_product_reference": "product-prefix"})
	b, _ := json.Marshal(x)
	r.Document = string(b)
	got, e := Analyze(r)
	if e != nil {
		t.Fatal(e)
	}
	if !got.Statuses[0].Relevant {
		t.Fatal("nested relationship did not resolve")
	}
	r.Document = strings.Replace(r.Document, `"product_id":"not-affected-status"`, `"product_id":"missing"`, 1)
	got, e = Analyze(r)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, s := range got.Statuses {
		for _, st := range s.Steps {
			if strings.Contains(st.Result, "No default_component_of") {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("missing relationship not explained")
	}
}

func TestRealDocument(t *testing.T) {
	path := os.Getenv("VEX_TEST_DOCUMENT")
	if path == "" {
		t.Skip("set VEX_TEST_DOCUMENT for a real Red Hat document")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	r := demo(t)
	if cve := os.Getenv("VEX_TEST_CVE"); cve != "" {
		r.CVE = cve
	} else {
		r.CVE = "CVE-2024-24786"
	}
	if labelsPath := os.Getenv("VEX_TEST_LABELS"); labelsPath != "" {
		labels, readErr := os.ReadFile(labelsPath)
		if readErr != nil {
			t.Fatal(readErr)
		}
		r.Labels = string(labels)
	}
	r.Document = string(b)
	report, e := Analyze(r)
	if e != nil {
		t.Fatal(e)
	}
	if os.Getenv("VEX_TEST_LABELS") != "" {
		matched := 0
		for _, assertion := range report.Assertions {
			if assertion.Match {
				matched++
				if len(assertion.SourceStatusIDs) == 0 {
					t.Fatal("matched assertion has no source status IDs")
				}
			}
		}
		if matched == 0 {
			t.Fatal("expected the supplied real labels to match at least one assertion")
		}
	}
}
