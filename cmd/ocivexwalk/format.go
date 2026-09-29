package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/dcaravel/oci-vex-walk/internal/finder"
)

func printReports(out io.Writer, docs []documentReport, o options, imageName, imageCPE string) {
	o.progressStep(5, "Matching component names")
	section(out, 5, "Match OCI component names")
	for _, doc := range docs {
		r := doc.report
		matched := 0
		for _, c := range r.Candidates {
			if c.Match {
				matched++
			}
		}
		if r.GoldRepo {
			fmt.Fprintf(out, "  %s: %d of %d components match legacy package names\n", doc.name, matched, len(r.Candidates))
		} else {
			fmt.Fprintf(out, "  %s: %d of %d components match the image name\n", doc.name, matched, len(r.Candidates))
		}
		if doc.identity != "" {
			fmt.Fprintf(out, "    Identity: %s\n", doc.identity)
		}
		if r.GoldRepo {
			fmt.Fprintf(out, "    Names eligible for GoldRepo matching: %s\n", strings.Join(r.ImageNames, ", "))
		} else if len(r.ImageNames) > 0 {
			fmt.Fprintf(out, "    Image name: %q (from this labels.json identity)\n", r.ImageNames[0])
		}
		seen := map[string]bool{}
		values := []finder.Candidate{}
		unavailable := 0
		for _, c := range r.Candidates {
			key := c.Derived
			if key == "" {
				key = "\x00" + c.PURL
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			values = append(values, c)
			if c.Derived == "" {
				unavailable++
			}
		}
		fmt.Fprintf(out, "    Component names found in VEX: %d distinct\n", len(values)-unavailable)
		if len(values) == 0 {
			fmt.Fprintln(out, "      No OCI component names were found in this document.")
		}
		for _, c := range values {
			if c.Derived == "" {
				fmt.Fprintf(out, "      Candidate name: unavailable (could not derive from PURL %q)\n", c.PURL)
			} else {
				fmt.Fprintf(out, "      Candidate name: %q (%s)\n", c.Derived, verdict(c.Match))
			}
		}
		for _, c := range r.Candidates {
			if !c.Match && !o.verbose {
				continue
			}
			fmt.Fprintf(out, "    %s: %s\n", verdict(c.Match), c.ID)
			fmt.Fprintf(out, "      Name from PURL: %q\n      PURL: %s\n", c.Derived, c.PURL)
			for _, s := range c.Steps {
				if s.Title == "Namespace present" || s.Title == "repository_url found" || s.Title == "repository_url absent" || s.Title == "Repository path" || (o.verbose && s.Title == "Architecture (informational)") {
					fmt.Fprintf(out, "      %s\n", s.Result)
				}
			}
		}
	}

	o.progressStep(6, "Matching product CPEs")
	section(out, 6, "Match product CPEs")
	for _, doc := range docs {
		r := doc.report
		matched := 0
		for _, p := range r.Products {
			if p.Match {
				matched++
			}
		}
		if r.GoldRepo {
			fmt.Fprintf(out, "  %s: %d of %d advisory products are eligible through GoldRepo\n", doc.name, matched, len(r.Products))
		} else {
			fmt.Fprintf(out, "  %s: %d of %d products match the image CPE\n", doc.name, matched, len(r.Products))
		}
		if doc.identity != "" {
			fmt.Fprintf(out, "    Identity: %s\n", doc.identity)
		}
		if r.GoldRepo {
			fmt.Fprintln(out, "    GoldRepo: advisory CPE is not compared; Claircore matches by RHCC repository key and package name.")
		} else if imageCPE != "" {
			fmt.Fprintf(out, "    Image CPE: %s (from this labels.json identity)\n", imageCPE)
		}
		seen := map[string]bool{}
		values := []finder.ProductCheck{}
		for _, p := range r.Products {
			if seen[p.CPE] {
				continue
			}
			seen[p.CPE] = true
			values = append(values, p)
		}
		fmt.Fprintf(out, "    Product CPEs found in VEX: %d distinct\n", len(values))
		if len(values) == 0 {
			fmt.Fprintln(out, "      No product CPEs were found in this document.")
		}
		for _, p := range values {
			result := verdict(p.Match)
			if r.GoldRepo {
				result = "eligible through GoldRepo; not compared"
			}
			fmt.Fprintf(out, "      Advisory CPE: %s (%s)\n", p.CPE, result)
		}
		for _, p := range r.Products {
			if !p.Match && !o.verbose {
				continue
			}
			fmt.Fprintf(out, "    %s: %s\n      CPE: %s\n", verdict(p.Match), p.ID, p.CPE)
			for _, s := range p.Steps {
				if s.Title == "Standard CPE comparison" || s.Title == "Red Hat prefix fallback" {
					fmt.Fprintf(out, "      %s: %s\n", s.Title, s.Result)
				}
			}
		}
	}

	o.progressStep(7, "Following CSAF status relationships")
	section(out, 7, "Follow CSAF status relationships")
	fmt.Fprintln(out, "  A MATCH here links a VEX component name to an advisory product; Step 8 still checks package kind, package name, and version.")
	for _, doc := range docs {
		r := doc.report
		relevant := 0
		for _, s := range r.Statuses {
			if s.Relevant {
				relevant++
			}
		}
		fmt.Fprintf(out, "  %s: %d of %d status rows join a matched component and product\n", doc.name, relevant, len(r.Statuses))
		if doc.identity != "" {
			fmt.Fprintf(out, "    Identity: %s\n", doc.identity)
		}
		if relevant == 0 {
			fmt.Fprintln(out, "    No status relationship connects both matching identities in this document.")
		}
		for _, s := range r.Statuses {
			if !s.Relevant && !o.verbose {
				continue
			}
			fmt.Fprintf(out, "    %s: %s (%s)\n", verdict(s.Relevant), s.ID, s.Status)
			fmt.Fprintf(out, "      Component name: %s\n      Product CPE: %s\n", s.PackageName, s.RepositoryCPE)
			for _, st := range s.Steps {
				if st.Title == "Interpret status" {
					fmt.Fprintf(out, "      Meaning: %s\n", st.Result)
				}
			}
			if s.Relevant && s.Status == "known_affected" && r.SourcePackageName != "" && s.PackageName != r.SourcePackageName {
				fmt.Fprintf(out, "      Source package check: VEX name %q differs from image source package %q; this linked row cannot match a source-package assertion.\n", s.PackageName, r.SourcePackageName)
			}
		}
	}

	o.progressStep(8, "Checking Claircore assertions")
	section(out, 8, "Check Claircore assertions")
	for _, doc := range docs {
		r := doc.report
		matched := 0
		for _, a := range r.Assertions {
			if a.Match {
				matched++
			}
		}
		fmt.Fprintf(out, "  %s: %d of %d assertions match this image\n", doc.name, matched, len(r.Assertions))
		if doc.identity != "" {
			fmt.Fprintf(out, "    Identity: %s\n", doc.identity)
		}
		for _, a := range r.Assertions {
			kind := "affected"
			if a.Invert {
				kind = "not affected"
			}
			fmt.Fprintf(out, "    %s: %s (%s package)\n", verdict(a.Match), a.Name, kind)
			fmt.Fprintf(out, "      Repository CPE: %s\n", a.RepositoryCPE)
			if r.GoldRepo {
				fmt.Fprintln(out, "      Image repository: GoldRepo")
			}
			if a.Fixed != "" {
				fmt.Fprintf(out, "      Fixed version: %s\n", a.Fixed)
			}
			if len(a.SourceStatusIDs) > 0 {
				fmt.Fprintf(out, "      CSAF status IDs: %s\n", strings.Join(a.SourceStatusIDs, ", "))
			}
			for _, s := range a.Steps {
				if s.Title == "Database version-range filter" || s.Title == "RHCC matcher" || s.Title == "Standard CPE comparison" || s.Title == "Red Hat prefix fallback" {
					fmt.Fprintf(out, "      %s: %s\n", s.Title, s.Result)
				}
			}
		}
		fmt.Fprintf(out, "    Conclusion: %s\n", r.Summary)
		if names, ok := linkedSourceNameMismatch(r); ok && len(r.Assertions) == 0 {
			fmt.Fprintf(out, "    Note: Linked known_affected rows name %s, but the image source package is %q. Claircore emits known_affected assertions for source packages, so none match this image.\n", strings.Join(names, "; "), r.SourcePackageName)
		}
		for _, warning := range r.Warnings {
			if !strings.HasPrefix(warning, "Scope:") && !strings.HasPrefix(warning, "Architecture is shown") {
				fmt.Fprintf(out, "    Note: %s\n", warning)
			}
		}
	}

	o.progressStep(9, "Comparing feed conclusions")
	summary := printConclusions(out, docs)
	if imageName == "" && o.summary != nil {
		imageName, imageCPE = o.summary.DetectedName, o.summary.DetectedCPE
	}
	summary.DetectedName, summary.DetectedCPE = imageName, imageCPE
	if o.summary != nil {
		*o.summary = summary
	}
}

func verdict(match bool) string {
	if match {
		return "MATCH"
	}
	return "SKIP"
}

type feedConclusion struct {
	components  int
	products    int
	statuses    int
	affected    int
	notAffected int
	complete    bool
}

type feedDecision struct {
	Available bool
	Label     string
	Reason    string
}

type walkSummary struct {
	Current                   feedDecision
	Legacy                    feedDecision
	DetectedName, DetectedCPE string
}

func (s walkSummary) currentDecision() feedDecision {
	if s.Current.Available {
		return s.Current
	}
	return feedDecision{Label: "Unavailable", Reason: "No new VEX feed document was loaded."}
}

func (s walkSummary) legacyDecision() feedDecision {
	if s.Legacy.Available {
		return s.Legacy
	}
	return feedDecision{Label: "Unavailable", Reason: "No old VEX feed document was loaded."}
}

func (s *walkSummary) markImageIncomplete(label, reason string) {
	if s == nil {
		return
	}
	decision := feedDecision{Available: true, Label: label, Reason: reason}
	s.Current, s.Legacy = decision, decision
}

func renderText(out io.Writer, summary walkSummary, trace string) error {
	current, legacy := summary.currentDecision(), summary.legacyDecision()
	_, err := fmt.Fprintf(out, "Conclusion (New VEX feed): %s\n  %s\nOld VEX feed: %s\n  %s\n\n%s", current.Label, current.Reason, legacy.Label, legacy.Reason, trace)
	return err
}

// renderCSV emits one spreadsheet row for the selected image and CVE. The
// conclusions are VEX matching conclusions, not StackRox OSV scan outcomes.
func renderCSV(out io.Writer, o options, summary walkSummary) error {
	w := csv.NewWriter(out)
	if err := w.Write([]string{"image", "cve", "detected_name", "detected_cpe", "old_vex_conclusion", "new_vex_conclusion"}); err != nil {
		return err
	}
	image := o.image
	if image == "" {
		image = o.archive
	}
	old, current := summary.legacyDecision(), summary.currentDecision()
	if err := w.Write([]string{image, strings.ToUpper(strings.TrimSpace(o.cve)), summary.DetectedName, summary.DetectedCPE, old.Label, current.Label}); err != nil {
		return err
	}
	w.Flush()
	return w.Error()
}

func conclude(r *finder.Report) feedConclusion {
	c := feedConclusion{complete: r.VulnerabilityReport != nil}
	for _, candidate := range r.Candidates {
		if candidate.Match {
			c.components++
		}
	}
	for _, product := range r.Products {
		if product.Match {
			c.products++
		}
	}
	for _, status := range r.Statuses {
		if status.Relevant {
			c.statuses++
		}
	}
	for _, assertion := range r.Assertions {
		if !assertion.Match {
			continue
		}
		if assertion.Invert {
			c.notAffected++
		} else {
			c.affected++
		}
	}
	return c
}

func (c feedConclusion) decision() feedDecision {
	if !c.complete {
		return feedDecision{Available: true, Label: "Incomplete", Reason: "Matching could not be completed for every eligible image identity in this feed."}
	}
	switch {
	case c.affected > 0 && c.notAffected > 0:
		return feedDecision{Available: true, Label: "Conflicting evidence", Reason: "Affected and not affected assertions both match; Claircore reports them separately."}
	case c.affected > 0:
		return feedDecision{Available: true, Label: "Affected", Reason: "At least one affected assertion matches this image."}
	case c.notAffected > 0:
		return feedDecision{Available: true, Label: "Not affected", Reason: "Only not affected assertions match this image."}
	default:
		return feedDecision{Available: true, Label: "No matching assertion", Reason: "No matching assertion was found; this does not establish that the image is safe or fixed."}
	}
}

func printConclusions(out io.Writer, docs []documentReport) walkSummary {
	section(out, 9, "VEX conclusions")
	conclusions := map[string]feedConclusion{}
	identityDetails := map[string][]string{}
	summary := walkSummary{}
	for _, doc := range docs {
		c := conclude(doc.report)
		combined, found := conclusions[doc.name]
		if !found {
			combined.complete = true
		}
		combined.complete = combined.complete && c.complete
		combined.components += c.components
		combined.products += c.products
		combined.statuses += c.statuses
		combined.affected += c.affected
		combined.notAffected += c.notAffected
		conclusions[doc.name] = combined
		if doc.identity != "" {
			detail := fmt.Sprintf("%s: %d affected, %d not affected", doc.identity, c.affected, c.notAffected)
			if !c.complete {
				detail += " (incomplete)"
			}
			identityDetails[doc.name] = append(identityDetails[doc.name], detail)
		}
	}
	for _, name := range []string{"Old VEX feed", "New VEX feed"} {
		c, found := conclusions[name]
		if !found {
			continue
		}
		decision := c.decision()
		if decision.Label == "No matching assertion" {
			decision = explainNoMatch(c, docs, name)
		} else if decision.Label == "Affected" || decision.Label == "Not affected" {
			var identities []string
			var example string
			seen := make(map[string]bool)
			for _, doc := range docs {
				if doc.name != name {
					continue
				}
				for _, assertion := range doc.report.Assertions {
					if !assertion.Match || (decision.Label == "Affected") == assertion.Invert {
						continue
					}
					identity := doc.identity
					if doc.report.GoldRepo {
						identity += " (GoldRepo; advisory CPE not compared)"
					}
					if !seen[identity] {
						identities = append(identities, identity)
						seen[identity] = true
					}
					if example == "" {
						example = fmt.Sprintf("package %q", assertion.Name)
						if assertion.Fixed != "" {
							example += fmt.Sprintf(", fixed version %q", assertion.Fixed)
						}
						if len(assertion.SourceStatusIDs) > 0 {
							example += fmt.Sprintf(", CSAF status %q", assertion.SourceStatusIDs[0])
						}
					}
				}
			}
			if len(identities) > 0 {
				kind, count := "affected", c.affected
				if decision.Label == "Not affected" {
					kind, count = "not affected", c.notAffected
				}
				decision.Reason = fmt.Sprintf("%d %s assertions matched via %s. Example: %s. See the linked status and assertion evidence in Steps 7–9.", count, kind, strings.Join(identities, ", "), example)
			}
		}
		if name == "Old VEX feed" {
			summary.Legacy = decision
		} else {
			summary.Current = decision
		}
		fmt.Fprintf(out, "  %s\n", name)
		for _, detail := range identityDetails[name] {
			fmt.Fprintf(out, "    Identity: %s\n", detail)
		}
		fmt.Fprintf(out, "    Identity checks: %d component names, %d product CPEs, %d linked status rows\n", c.components, c.products, c.statuses)
		fmt.Fprintf(out, "    Matched assertions: %d affected, %d not affected\n", c.affected, c.notAffected)
		fmt.Fprintf(out, "    Conclusion: %s\n    Reason: %s\n", decision.Label, decision.Reason)
	}
	return summary
}

// linkedSourceNameMismatch identifies the case where Step 7 finds only
// known_affected rows through a binary/ancestry name, while Claircore's parser
// emits those rows as source-package assertions.
func linkedSourceNameMismatch(r *finder.Report) ([]string, bool) {
	if r == nil || r.SourcePackageName == "" {
		return nil, false
	}
	seen := make(map[string]bool)
	for _, status := range r.Statuses {
		if !status.Relevant {
			continue
		}
		if status.Status != "known_affected" || status.PackageName == r.SourcePackageName {
			return nil, false
		}
		seen[status.PackageName] = true
	}
	if len(seen) == 0 {
		return nil, false
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, true
}

func explainNoMatch(c feedConclusion, docs []documentReport, feed string) feedDecision {
	decision := feedDecision{Available: true}
	const caution = " This does not establish that the image is safe or fixed."
	goldRepo := false
	nameSet := make(map[string]bool)
	for _, doc := range docs {
		if doc.name != feed {
			continue
		}
		if doc.report.GoldRepo {
			goldRepo = true
		}
		for _, name := range doc.report.ImageNames {
			if name != "" {
				nameSet[name] = true
			}
		}
	}
	switch {
	case c.components == 0:
		if goldRepo {
			decision.Label = "No matching assertion — no eligible package name found"
			var names []string
			for name := range nameSet {
				names = append(names, name)
			}
			sort.Strings(names)
			decision.Reason = "No OCI component name in this VEX feed matched any eligible Claircore package name"
			if len(names) > 0 {
				decision.Reason += ": " + strings.Join(names, "; ")
			}
			decision.Reason += "." + caution
		} else {
			decision.Label = "No matching assertion — OCI name not found"
			decision.Reason = "No OCI component name in this VEX feed matched the selected labels.json image name." + caution
		}
	case c.products == 0:
		if goldRepo {
			decision.Label = "No matching assertion — advisory product not found"
			decision.Reason = "The OCI name matched, but no advisory product was eligible for the image identity." + caution
		} else {
			decision.Label = "No matching assertion — product CPE not found"
			decision.Reason = "The OCI name matched, but no advisory product CPE matched the selected image repository." + caution
		}
	case c.statuses == 0:
		if goldRepo {
			decision.Label = "No matching assertion — name/product not linked"
		} else {
			decision.Label = "No matching assertion — name/CPE not linked"
		}
		decision.Reason = "The name and product matched separately, but no CSAF status relationship linked them for this image." + caution
	default:
		var assertions []finder.Assertion
		for _, doc := range docs {
			if doc.name == feed {
				assertions = append(assertions, doc.report.Assertions...)
			}
		}
		if len(assertions) == 0 {
			var mismatchedNames []string
			var sourceNames []string
			matchedOnlyByOtherKind := true
			for _, doc := range docs {
				if doc.name != feed {
					continue
				}
				hasLinkedStatus := false
				for _, status := range doc.report.Statuses {
					if status.Relevant {
						hasLinkedStatus = true
						break
					}
				}
				if !hasLinkedStatus {
					continue
				}
				names, ok := linkedSourceNameMismatch(doc.report)
				if !ok {
					matchedOnlyByOtherKind = false
					break
				}
				mismatchedNames = append(mismatchedNames, names...)
				sourceNames = append(sourceNames, doc.report.SourcePackageName)
			}
			if matchedOnlyByOtherKind && len(mismatchedNames) > 0 {
				decision.Label = "No matching assertion — source package name mismatch"
				decision.Reason = fmt.Sprintf("Linked known_affected rows name %s, but the image source package is %s. Claircore emits known_affected assertions for source packages, so none match this image.", strings.Join(mismatchedNames, "; "), strings.Join(sourceNames, "; ")) + caution
			} else {
				decision.Label = "No matching assertion — linked status, no assertion"
				decision.Reason = "A CSAF status linked the name and product, but Claircore emitted no matching assertion from it." + caution
			}
			return decision
		}
		cpeRejected, rangeRejected, fixedRejected := 0, 0, 0
		for _, assertion := range assertions {
			cpeMatched, rangeMatched := false, false
			matcherRejected := false
			for _, step := range assertion.Steps {
				switch step.Title {
				case "GoldRepo matching", "Standard CPE comparison", "Red Hat prefix fallback":
					if step.Title == "GoldRepo matching" || strings.HasSuffix(step.Result, ": true") {
						cpeMatched = true
					}
				case "Database version-range filter":
					rangeMatched = strings.HasSuffix(step.Result, ": true")
				case "RHCC matcher":
					matcherRejected = strings.HasSuffix(step.Result, "Match: false")
				}
			}
			switch {
			case !cpeMatched:
				cpeRejected++
			case !rangeMatched:
				rangeRejected++
			case matcherRejected && assertion.Fixed != "":
				fixedRejected++
			}
		}
		switch {
		case cpeRejected == len(assertions):
			decision.Label = "No matching assertion — assertion CPE mismatch"
			decision.Reason = "The linked status was found, but Claircore rejected the parsed assertions on repository CPE." + caution
		case rangeRejected == len(assertions):
			decision.Label = "No matching assertion — version outside range"
			decision.Reason = "The linked status was found, but the image version fell outside the parsed assertion ranges." + caution
		case fixedRejected == len(assertions):
			decision.Label = "No matching assertion — fixed-version check"
			decision.Reason = "The linked fixed assertions did not match the image under Claircore's version comparison." + caution
		default:
			decision.Label = "No matching assertion — linked assertions rejected"
			decision.Reason = "The name, product, and CSAF status linked, but no parsed assertion passed all Claircore checks." + caution
		}
	}
	return decision
}
