// Package finder explains OCI lookups and evaluates assertions using Claircore.
package finder

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/package-url/packageurl-go"
	"github.com/quay/claircore"
	"github.com/quay/claircore/pkg/rhctag"
	"github.com/quay/claircore/rhel"
	"github.com/quay/claircore/rhel/rhcc"
	"github.com/quay/claircore/rhel/vex"
	"github.com/quay/claircore/toolkit/types"
	"github.com/quay/claircore/toolkit/types/cpe"
	"github.com/quay/claircore/toolkit/types/csaf"
)

type Request struct {
	Labels   string          `json:"labels"`
	CVE      string          `json:"cve"`
	Document string          `json:"document"`
	Legacy   *LegacyIdentity `json:"legacy,omitempty"`
}

// LegacyIdentity is the package identity emitted by Claircore's Dockerfile scanner.
// Repositories contains the mapped binary/ancestry package names, or the name
// label when the mapping has no entry.
type LegacyIdentity struct {
	Path, Name, Component, Architecture, Version string
	Repositories                                 []string
}
type Step struct {
	Title  string `json:"title"`
	Result string `json:"result"`
	Detail any    `json:"detail,omitempty"`
}
type Candidate struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	PURL    string `json:"purl"`
	Derived string `json:"derived"`
	Match   bool   `json:"match"`
	Steps   []Step `json:"steps"`
}
type ProductCheck struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	CPE   string `json:"cpe"`
	Match bool   `json:"match"`
	Steps []Step `json:"steps"`
}
type Status struct {
	ID            string `json:"id"`
	Status        string `json:"status"`
	Relevant      bool   `json:"relevant"`
	PackageName   string `json:"package_name,omitempty"`
	RepositoryCPE string `json:"repository_cpe,omitempty"`
	PURL          string `json:"purl,omitempty"`
	Architecture  string `json:"architecture,omitempty"`
	Tag           string `json:"tag,omitempty"`
	Steps         []Step `json:"steps"`
}
type Assertion struct {
	RepresentativeStatusID string   `json:"representative_status_id,omitempty"`
	SourceStatusIDs        []string `json:"source_status_ids"`
	Name                   string   `json:"name"`
	Kind                   string   `json:"kind"`
	Invert                 bool     `json:"invert"`
	Match                  bool     `json:"match"`
	Fixed                  string   `json:"fixed"`
	Architectures          string   `json:"architectures"`
	RepositoryCPE          string   `json:"repository_cpe"`
	Steps                  []Step   `json:"steps"`
}
type Report struct {
	Identity                string                         `json:"identity,omitempty"`
	ImageNames              []string                       `json:"image_names,omitempty"`
	GoldRepo                bool                           `json:"gold_repo,omitempty"`
	ParserDiagnostics       []json.RawMessage              `json:"parser_diagnostics"`
	CVE                     string                         `json:"cve"`
	Summary                 string                         `json:"summary"`
	Steps                   []Step                         `json:"steps"`
	Candidates              []Candidate                    `json:"candidates"`
	Products                []ProductCheck                 `json:"products"`
	Statuses                []Status                       `json:"statuses"`
	Assertions              []Assertion                    `json:"assertions"`
	Warnings                []string                       `json:"warnings"`
	Context                 any                            `json:"context"`
	VulnerabilityReport     *claircore.VulnerabilityReport `json:"vulnerability_report"`
	VulnerabilityReportNote string                         `json:"vulnerability_report_note"`
}
type labels struct {
	Name    string    `json:"name"`
	Arch    string    `json:"architecture"`
	CPE     string    `json:"cpe"`
	Created time.Time `json:"org.opencontainers.image.created"`
}

var cvePattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

func step(title, result string, detail any) Step { return Step{title, result, detail} }

func derive(raw, want, arch string) Candidate {
	c := Candidate{PURL: raw}
	p, err := packageurl.FromString(raw)
	if err != nil {
		c.Steps = append(c.Steps, step("Parse PURL", "Invalid: "+err.Error(), nil))
		return c
	}
	c.Steps = append(c.Steps, step("Parse PURL", "Decoded using packageurl-go", p))
	if p.Type != "oci" {
		c.Steps = append(c.Steps, step("Package type", "Not OCI; excluded", p.Type))
		return c
	}
	if p.Namespace != "" {
		c.Derived = p.Namespace + "/" + p.Name
		c.Steps = append(c.Steps, step("Namespace present", "Use namespace + / + name; repository_url fallback not needed", c.Derived))
	} else {
		c.Steps = append(c.Steps, step("Namespace absent", "Look for repository_url qualifier", nil))
		ru, found := "", false
		for _, q := range p.Qualifiers {
			if q.Key == "repository_url" {
				ru = q.Value
				found = true
			}
		}
		if found {
			_, image, ok := strings.Cut(ru, "/")
			c.Steps = append(c.Steps, step("repository_url found", "Remove everything through the first slash (Claircore behavior)", ru))
			if !ok {
				c.Steps = append(c.Steps, step("Repository path", "Invalid: no slash; do not fall back to bare name", nil))
				return c
			}
			c.Derived = image
		} else {
			c.Derived = p.Name
			c.Steps = append(c.Steps, step("repository_url absent", "Fall back to the PURL name", p.Name))
		}
	}
	c.Match = c.Derived == want
	c.Steps = append(c.Steps, step("Compare with labels.name", fmt.Sprintf("Exact name match: %t", c.Match), map[string]string{"derived": c.Derived, "labels.name": want}))
	pa := ""
	for _, q := range p.Qualifiers {
		if q.Key == "arch" {
			pa = q.Value
		}
	}
	compatible := pa == "" || pa == arch || ((pa == "amd64" || pa == "x86_64") && (arch == "amd64" || arch == "x86_64"))
	c.Steps = append(c.Steps, step("Architecture (informational)", fmt.Sprintf("Compatible: %t. RHCC does not reject matches on architecture in this checkout.", compatible), map[string]string{"purl": pa, "labels": arch}))
	return c
}

func compareCPE(raw string, image cpe.WFN) (bool, []Step) {
	target, err := cpe.Unbind(raw)
	if err != nil {
		return false, []Step{step("Parse advisory CPE", "Invalid: "+err.Error(), raw)}
	}
	steps := []Step{step("Normalize CPEs", "Convert both to CPE formatted strings", map[string]string{"image": image.String(), "advisory": target.String()})}
	standard := cpe.Compare(target, image).IsSuperset()
	steps = append(steps, step("Standard CPE comparison", fmt.Sprintf("Advisory is a superset of, or equal to, image: %t", standard), nil))
	if standard {
		return true, append(steps, step("Red Hat prefix fallback", "Not needed", nil))
	}
	prefix := strings.TrimRight(target.String(), ":*")
	fallback := rhel.IsCPESubstringMatch(image, target)
	steps = append(steps, step("Red Hat prefix fallback", fmt.Sprintf("Image CPE starts with trimmed advisory CPE: %t", fallback), map[string]string{"prefix": prefix, "image": image.String()}))
	return fallback, steps
}

func Analyze(req Request) (*Report, error) {
	req.CVE = strings.ToUpper(strings.TrimSpace(req.CVE))
	if !cvePattern.MatchString(req.CVE) {
		return nil, fmt.Errorf("enter a CVE such as CVE-2024-24786")
	}
	report := &Report{CVE: req.CVE, Candidates: []Candidate{}, Products: []ProductCheck{}, Statuses: []Status{}, Assertions: []Assertion{}, Warnings: []string{}}
	var l labels
	var imageCPE cpe.WFN
	var version string
	var normalized claircore.Version
	nameSet := map[string]bool{}
	if req.Legacy != nil {
		legacy := req.Legacy
		if legacy.Path == "" || legacy.Name == "" || legacy.Component == "" || legacy.Architecture == "" || legacy.Version == "" {
			return nil, fmt.Errorf("legacy Dockerfile identity needs a path, name, component, architecture, and version")
		}
		l.Name, l.Arch = legacy.Name, legacy.Architecture
		version = legacy.Version
		parsed, err := rhctag.Parse(version)
		if err != nil {
			return nil, fmt.Errorf("legacy Dockerfile version %q: %w", version, err)
		}
		minorStart := parsed.MinorStart()
		normalized = minorStart.Version(true)
		nameSet[legacy.Component] = true
		for _, name := range legacy.Repositories {
			if name != "" {
				nameSet[name] = true
			}
		}
		report.Identity, report.GoldRepo = "legacy Dockerfile", true
		report.Steps = append(report.Steps, step("1. Read legacy Dockerfile", "Claircore emits a source package from com.redhat.component and binary/ancestry packages from the name mapping; repository is GoldRepo.", legacy), step("2. Derive image version", "Extract version-release from the Dockerfile filename; normalize to the minor-range start with rhctag", map[string]any{"version": version, "normalized": normalized}))
	} else {
		if err := json.Unmarshal([]byte(req.Labels), &l); err != nil {
			return nil, fmt.Errorf("labels.json: %w", err)
		}
		for _, v := range []struct {
			key string
			p   *string
		}{{"name", &l.Name}, {"architecture", &l.Arch}, {"cpe", &l.CPE}} {
			if s, e := strconv.Unquote(*v.p); e == nil {
				report.Steps = append(report.Steps, step("Normalize "+v.key, "Removed an extra layer of JSON quoting", map[string]string{"before": *v.p, "after": s}))
				*v.p = s
			}
		}
		if l.Name == "" || l.Arch == "" || l.Created.IsZero() {
			return nil, fmt.Errorf("labels.json requires nonempty name, architecture and a valid org.opencontainers.image.created timestamp")
		}
		if l.CPE == "" {
			return nil, fmt.Errorf("labels.json has no cpe: Claircore creates no JSON-derived RHCC repository, so this identity cannot match on its own")
		}
		var err error
		imageCPE, err = cpe.Unbind(l.CPE)
		if err != nil {
			return nil, fmt.Errorf("labels.json CPE: %w", err)
		}
		version = strconv.FormatInt(l.Created.Unix(), 10)
		parsedVersion, err := rhctag.Parse(version)
		if err != nil {
			return nil, err
		}
		normalized = parsedVersion.Version(true)
		nameSet[l.Name] = true
		report.Identity = "labels.json"
		report.Steps = append(report.Steps, step("1. Read labels.json", "Source, binary and ancestry packages all use name directly. No name-to-repository mapping.", l), step("2. Derive image version", "Convert creation time to Unix seconds; normalize with rhctag", map[string]any{"version": version, "normalized": normalized, "cpe": imageCPE.String()}))
	}
	for name := range nameSet {
		report.ImageNames = append(report.ImageNames, name)
	}
	sort.Strings(report.ImageNames)
	doc, err := csaf.Parse(strings.NewReader(req.Document))
	if err != nil {
		return nil, err
	}
	selected := []csaf.Vulnerability{}
	for _, v := range doc.Vulnerabilities {
		if strings.EqualFold(v.CVE, req.CVE) {
			selected = append(selected, v)
		}
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("document contains no vulnerability entry for %s; check the CVE and file", req.CVE)
	}
	doc.Vulnerabilities = selected
	// Preserve the raw vulnerability entries below for flags and fields not modeled by Claircore.
	report.Steps = append(report.Steps, step("3. Read CSAF document", "Select requested CVE; retain the complete product tree", doc.Document))
	if doc.Document.Tracking.Status == "deleted" {
		report.Warnings = append(report.Warnings, "This document is marked deleted. Its historical status entries are not current assertions.")
	}
	products := map[string]csaf.Product{}
	candidates := map[string]Candidate{}
	checks := map[string]ProductCheck{}
	var walk func(csaf.ProductBranch)
	walk = func(b csaf.ProductBranch) {
		if b.Product.ID != "" {
			products[b.Product.ID] = b.Product
		}
		for _, child := range b.Branches {
			walk(child)
		}
	}
	walk(doc.ProductTree)
	ids := make([]string, 0, len(products))
	for id := range products {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		p := products[id]
		if raw := p.IdentificationHelper["purl"]; strings.HasPrefix(raw, "pkg:oci/") {
			c := derive(raw, l.Name, l.Arch)
			if req.Legacy != nil {
				c.Match = nameSet[c.Derived]
				for i := range c.Steps {
					if c.Steps[i].Title == "Compare with labels.name" {
						c.Steps[i] = step("Compare with Dockerfile packages", fmt.Sprintf("Matches source or mapped binary/ancestry package: %t", c.Match), report.ImageNames)
					}
				}
			}
			c.ID = id
			c.Name = p.Name
			candidates[id] = c
			report.Candidates = append(report.Candidates, c)
		}
		if raw := p.IdentificationHelper["cpe"]; raw != "" {
			ok, steps := true, []Step{step("GoldRepo matching", "Claircore's RHCC matcher does not compare advisory CPEs for GoldRepo records", raw)}
			if req.Legacy == nil {
				ok, steps = compareCPE(raw, imageCPE)
			}
			pc := ProductCheck{id, p.Name, raw, ok, steps}
			checks[id] = pc
			report.Products = append(report.Products, pc)
		}
	}
	rels := map[string]csaf.Relationship{}
	for _, r := range doc.ProductTree.Relationships {
		if r.Category == "default_component_of" {
			rels[r.FullProductName.ID] = r
		}
	}
	resolve := func(id string, component bool) (string, []string, error) {
		path := []string{id}
		seen := map[string]bool{}
		for depth := 0; depth < 5; depth++ {
			r, ok := rels[id]
			if !ok {
				return id, path, nil
			}
			if seen[id] {
				return id, path, fmt.Errorf("relationship cycle")
			}
			seen[id] = true
			if component {
				id = r.ProductRef
			} else {
				id = r.RelatesToProductRef
			}
			path = append(path, id)
		}
		if _, ok := rels[id]; ok {
			return id, path, fmt.Errorf("relationship depth exceeds Claircore's five-hop limit")
		}
		return id, path, nil
	}
	totalStatus, unresolved := 0, 0
	for _, v := range selected {
		keys := make([]string, 0, len(v.ProductStatus))
		for k := range v.ProductStatus {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, status := range keys {
			for _, id := range v.ProductStatus[status] {
				totalStatus++
				rel, ok := rels[id]
				if !ok {
					unresolved++
					report.Statuses = append(report.Statuses, Status{ID: id, Status: status, Steps: []Step{step("Relationship lookup", "No default_component_of relationship; Claircore skips this status ID", nil)}})
					continue
				}
				pkgID, pkgPath, pe := resolve(rel.ProductRef, true)
				repoID, repoPath, re := resolve(rel.RelatesToProductRef, false)
				c, oci := candidates[pkgID]
				pc := checks[repoID]
				if !oci {
					continue
				}
				s := Status{ID: id, Status: status, Relevant: c.Match && pc.Match, PackageName: c.Derived, RepositoryCPE: pc.CPE, PURL: c.PURL}
				if parsed, parseErr := packageurl.FromString(c.PURL); parseErr == nil {
					for _, qualifier := range parsed.Qualifiers {
						switch qualifier.Key {
						case "arch":
							s.Architecture = qualifier.Value
						case "tag":
							s.Tag = qualifier.Value
						}
					}
				}
				s.Steps = append(s.Steps, step("Resolve status ID", "Found default_component_of", rel), step("Follow component references", "Resolve PURL-bearing component", pkgPath), step("Follow product references", "Resolve CPE-bearing product", repoPath))
				if pe != nil || re != nil {
					s.Relevant = false
					s.Steps = append(s.Steps, step("Relationship traversal", "Unresolved", fmt.Sprint(pe, re)))
				}
				join := fmt.Sprintf("Name match: %t; CPE match: %t", c.Match, pc.Match)
				if req.Legacy != nil {
					join = fmt.Sprintf("Legacy package name match: %t; GoldRepo accepts the advisory product without a CPE comparison", c.Match)
				}
				s.Steps = append(s.Steps, step("Join identity checks", join, map[string]string{"component_id": pkgID, "repository_id": repoID, "name": c.Derived, "cpe": pc.CPE}))
				switch status {
				case "known_not_affected":
					s.Steps = append(s.Steps, step("Interpret status", "OCI not affected: ancestry assertion with Invert=true; discard tag/version/epoch; all-version range", nil))
				case "known_affected":
					s.Steps = append(s.Steps, step("Interpret status", "Source-package affected assertion with all-version range", nil))
				case "fixed":
					s.Steps = append(s.Steps, step("Interpret status", "Use the tag qualifier as the fixed version; apply the normalized range and RHCC comparison", nil))
				default:
					s.Steps = append(s.Steps, step("Interpret status", "Visible in CSAF; not ingested as an assertion by this Claircore parser", nil))
				}
				report.Statuses = append(report.Statuses, s)
			}
		}
	}
	report.Steps = append(report.Steps, step("4. Find OCI components and CPE products", fmt.Sprintf("%d OCI components; %d CPE products", len(report.Candidates), len(report.Products)), nil), step("5. Resolve status relationships", fmt.Sprintf("%d status references; %d missing default_component_of relationships", totalStatus, unresolved), nil))
	// Filter to the requested CVE without throwing away fields unknown to csaf.CSAF.
	var rawDoc map[string]json.RawMessage
	if err = json.Unmarshal([]byte(req.Document), &rawDoc); err != nil {
		return nil, err
	}
	var rawVulnerabilities []json.RawMessage
	if err = json.Unmarshal(rawDoc["vulnerabilities"], &rawVulnerabilities); err != nil {
		return nil, err
	}
	rawSelected := []json.RawMessage{}
	for _, entry := range rawVulnerabilities {
		var identity struct {
			CVE string `json:"cve"`
		}
		if err = json.Unmarshal(entry, &identity); err != nil {
			return nil, err
		}
		if strings.EqualFold(identity.CVE, req.CVE) {
			rawSelected = append(rawSelected, entry)
		}
	}
	report.Context = rawSelected
	rawDoc["vulnerabilities"], _ = json.Marshal(rawSelected)
	input, _ := json.Marshal(rawDoc)
	installLogs.Do(func() { slog.SetDefault(slog.New(traceHandler{fallback: slog.Default().Handler()})) })
	var diagnostics bytes.Buffer
	logContext := context.WithValue(context.Background(), logKey{}, slog.NewJSONHandler(&diagnostics, &slog.HandlerOptions{Level: slog.LevelWarn}))
	assertions, err := vex.NewParser(vex.WithProductIDInLinks()).Parse(logContext, input)
	report.ParserDiagnostics = []json.RawMessage{}
	for _, line := range bytes.Split(bytes.TrimSpace(diagnostics.Bytes()), []byte("\n")) {
		if len(line) > 0 {
			report.ParserDiagnostics = append(report.ParserDiagnostics, json.RawMessage(append([]byte(nil), line...)))
		}
	}
	if err != nil {
		report.Warnings = append(report.Warnings, "Claircore parser failed: "+err.Error())
		report.Summary = "Document inspected; matching could not be completed."
		return report, nil
	}
	matched, notAffected := 0, 0
	packageDB, sourceName, binaryNames := "labels.json", l.Name, []string{l.Name}
	if req.Legacy != nil {
		packageDB, sourceName, binaryNames = req.Legacy.Path, req.Legacy.Component, req.Legacy.Repositories
	}
	sourcePackage := &claircore.Package{ID: "image-source", Name: sourceName, Version: version, NormalizedVersion: normalized, PackageDB: packageDB, Arch: l.Arch, Kind: types.SourcePackage, RepositoryHint: "rhcc"}
	imageRepository := &claircore.Repository{ID: "image-repository", Name: imageCPE.String(), CPE: imageCPE, Key: rhcc.RepositoryKey}
	if req.Legacy != nil {
		*imageRepository = rhcc.GoldRepo
		imageRepository.ID = "image-repository"
	}
	packagesByKindAndName := map[string]*claircore.Package{fmt.Sprint(types.SourcePackage) + "\x00" + sourceName: sourcePackage}
	report.VulnerabilityReport = &claircore.VulnerabilityReport{
		Packages:     map[string]*claircore.Package{sourcePackage.ID: sourcePackage},
		Repositories: map[string]*claircore.Repository{imageRepository.ID: imageRepository},
		Environments: map[string][]*claircore.Environment{}, Distributions: map[string]*claircore.Distribution{},
		Vulnerabilities: map[string]*claircore.Vulnerability{}, PackageVulnerabilities: map[string][]string{}, PackageNotVulnerable: map[string][]string{}, Enrichments: map[string][]json.RawMessage{},
	}
	for i, name := range binaryNames {
		for _, kind := range []struct {
			name string
			kind types.PackageKind
		}{{"binary", types.BinaryPackage}, {"ancestry", types.AncestryPackage}} {
			id := "image-" + kind.name
			if i > 0 {
				id = fmt.Sprintf("image-%s-%d", kind.name, i)
			}
			pkg := &claircore.Package{ID: id, Name: name, Version: version, NormalizedVersion: normalized, PackageDB: packageDB, Arch: l.Arch, Kind: kind.kind, RepositoryHint: "rhcc", Source: sourcePackage}
			report.VulnerabilityReport.Packages[id] = pkg
			packagesByKindAndName[fmt.Sprint(kind.kind)+"\x00"+name] = pkg
		}
	}
	report.VulnerabilityReportNote = "Report-shaped preview built with Claircore's VulnerabilityReport type. image-* and assertion-* are local placeholder IDs because this walkthrough does not run Clair's indexer, vulnerability database, or datastore ID assignment."
	for _, v := range assertions {
		if v.Package == nil || v.Repo == nil || v.Repo.Key != rhcc.RepositoryKey {
			continue
		}
		matchedPackage := packagesByKindAndName[fmt.Sprint(v.Package.Kind)+"\x00"+v.Package.Name]
		if matchedPackage == nil {
			continue
		}
		a := Assertion{Name: v.Name, Kind: fmt.Sprint(v.Package.Kind), Invert: v.Invert, Fixed: v.FixedInVersion, Architectures: v.Package.Arch, RepositoryCPE: v.Repo.Name, SourceStatusIDs: []string{}}
		for _, link := range strings.Fields(v.Links) {
			if u, e := url.Parse(link); e == nil && u.Fragment != "" {
				a.RepresentativeStatusID = u.Fragment
				break
			}
		}
		expectedStatus := "known_affected"
		if v.Invert {
			expectedStatus = "known_not_affected"
		} else if v.FixedInVersion != "" {
			expectedStatus = "fixed"
		}
		for _, sourceStatus := range report.Statuses {
			if sourceStatus.Status != expectedStatus || sourceStatus.PackageName != v.Package.Name {
				continue
			}
			statusCPE, statusErr := cpe.Unbind(sourceStatus.RepositoryCPE)
			if statusErr != nil || statusCPE.String() != v.Repo.Name {
				continue
			}
			if expectedStatus == "fixed" && sourceStatus.Tag != v.FixedInVersion {
				continue
			}
			a.SourceStatusIDs = append(a.SourceStatusIDs, sourceStatus.ID)
		}
		if len(a.SourceStatusIDs) > 1 {
			a.Steps = append(a.Steps, step("Architecture rows collapsed", fmt.Sprintf("Claircore merged %d CSAF status rows into one assertion because its OCI deduplication key deliberately excludes the arch qualifier.", len(a.SourceStatusIDs)), map[string]any{"architectures": v.Package.Arch, "source_status_ids": a.SourceStatusIDs, "representative_status_id": a.RepresentativeStatusID}))
		}
		a.Steps = append(a.Steps, step("Parser output", "Actual output from Claircore's VEX parser (may combine architectures/status IDs)", v))
		cp, cs := true, []Step{step("GoldRepo matching", "No CPE comparison for a legacy GoldRepo record", v.Repo.Name)}
		if req.Legacy == nil {
			cp, cs = compareCPE(v.Repo.Name, imageCPE)
		}
		a.Steps = append(a.Steps, cs...)
		inRange := v.Range != nil && v.Range.Contains(&normalized)
		a.Steps = append(a.Steps, step("Database version-range filter", fmt.Sprintf("Image normalized version in [lower, upper): %t", inRange), v.Range))
		record := &claircore.IndexRecord{Package: matchedPackage, Repository: imageRepository}
		if cp && inRange {
			ok, e := rhcc.Matcher.Vulnerable(context.Background(), record, v)
			a.Match = ok && e == nil
			if e != nil {
				a.Steps = append(a.Steps, step("RHCC matcher", "Error: "+e.Error(), nil))
			} else {
				reason := "Compare image version with fixed version using RPM EVR ordering"
				if v.Invert {
					reason = "Invert=true: skip version comparison"
				} else if v.FixedInVersion == "" {
					reason = "No fixed version: match"
				}
				a.Steps = append(a.Steps, step("RHCC matcher", fmt.Sprintf("%s. Match: %t", reason, ok), map[string]string{"image": version, "fixed": v.FixedInVersion}))
			}
		} else {
			reason := "Not reached: CPE or version-range filter rejected this assertion"
			if req.Legacy != nil {
				reason = "Not reached: version-range filter rejected this GoldRepo assertion"
			}
			a.Steps = append(a.Steps, step("RHCC matcher", reason, nil))
		}
		if a.Match {
			assertionID := fmt.Sprintf("assertion-%d", len(report.VulnerabilityReport.Vulnerabilities)+1)
			matchedVulnerability := *v
			matchedVulnerability.ID = assertionID
			report.VulnerabilityReport.Vulnerabilities[assertionID] = &matchedVulnerability
			packageID := matchedPackage.ID
			if a.Invert {
				notAffected++
				report.VulnerabilityReport.PackageNotVulnerable[packageID] = append(report.VulnerabilityReport.PackageNotVulnerable[packageID], assertionID)
			} else {
				matched++
				report.VulnerabilityReport.PackageVulnerabilities[packageID] = append(report.VulnerabilityReport.PackageVulnerabilities[packageID], assertionID)
			}
		}
		report.Assertions = append(report.Assertions, a)
	}
	report.Steps = append(report.Steps, step("6. Evaluate ingested assertions", fmt.Sprintf("%d emitted assertions with this OCI name; %d affected matches; %d not-affected matches", len(report.Assertions), matched, notAffected), nil))
	report.Summary = fmt.Sprintf("%d affected assertion(s); %d not-affected assertion(s).", matched, notAffected)
	if matched == 0 && notAffected == 0 {
		report.Summary = "No matching Claircore assertion. This does not establish that the image is not affected."
	}
	if matched > 0 && notAffected > 0 {
		report.Warnings = append(report.Warnings, "Both affected and not-affected assertions match. They are reported separately; invert does not suppress affected findings.")
	}
	report.Warnings = append(report.Warnings, "Scope: identity assumed to be from the latest qualifying RHCC layer. RPM findings and deployment-specific configuration are not inferred.", "Architecture is shown for inspection, not used as a rejection gate by this RHCC matcher. Parser output can combine several architecture-specific status IDs.")
	sort.SliceStable(report.Candidates, func(i, j int) bool { return report.Candidates[i].Match && !report.Candidates[j].Match })
	sort.SliceStable(report.Products, func(i, j int) bool { return report.Products[i].Match && !report.Products[j].Match })
	sort.SliceStable(report.Statuses, func(i, j int) bool { return report.Statuses[i].Relevant && !report.Statuses[j].Relevant })
	return report, nil
}
