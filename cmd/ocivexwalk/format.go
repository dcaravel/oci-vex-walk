package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/dcaravel/oci-vex-walk/internal/finder"
)

func printReports(out io.Writer, docs []documentReport, o options, imageName, imageCPE string) {
	o.progressStep(5, "Matching component names")
	section(out, 5, "Match OCI component names")
	if imageName != "" {
		fmt.Fprintf(out, "  Image name: %q (from selected labels.json)\n", imageName)
	}
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
	if imageCPE != "" {
		fmt.Fprintf(out, "  Image CPE: %s (from selected labels.json)\n", imageCPE)
	}
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
		for _, warning := range r.Warnings {
			if !strings.HasPrefix(warning, "Scope:") && !strings.HasPrefix(warning, "Architecture is shown") {
				fmt.Fprintf(out, "    Note: %s\n", warning)
			}
		}
	}

	o.progressStep(9, "Comparing feed conclusions")
	summary := printConclusions(out, docs)
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
	Current feedDecision
	Legacy  feedDecision
}

func (s walkSummary) currentDecision() feedDecision {
	if s.Current.Available {
		return s.Current
	}
	return feedDecision{Label: "Incomplete", Reason: "The new VEX feed was unavailable or matching did not reach a conclusion."}
}

func (s walkSummary) legacyDecision() feedDecision {
	if s.Legacy.Available {
		return s.Legacy
	}
	return feedDecision{Label: "Unavailable", Reason: "No old VEX feed conclusion is available."}
}

func renderText(out io.Writer, summary walkSummary, trace string) error {
	current, legacy := summary.currentDecision(), summary.legacyDecision()
	_, err := fmt.Fprintf(out, "Conclusion (New VEX feed): %s\n  %s\nOld VEX feed: %s\n  %s\n\n%s", current.Label, current.Reason, legacy.Label, legacy.Reason, trace)
	return err
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
