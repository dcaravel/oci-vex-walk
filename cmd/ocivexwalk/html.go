package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// The HTML view consumes the terminal trace, so both formats carry the same
// evidence and conclusions. html/template escapes document-controlled values.
type htmlLine struct {
	Text       string
	Label      string
	Value      string
	Link       string
	Parts      []htmlPart
	Code       bool
	Badge      string
	BadgeClass string
	Kind       string
	Depth      int
}

type htmlPart struct {
	Text string
	Code bool
}

type htmlItem struct {
	Heading htmlLine
	Details []htmlLine
}

type htmlBlock struct {
	Heading htmlLine
	Lines   []htmlLine
}

type htmlFeed struct {
	Name          string
	Identity      string
	Summary       string
	Lines         []htmlLine
	Values        []htmlLine
	Items         []htmlItem
	Skipped       []htmlItem
	ShowEvidence  bool
	CollapseItems bool
	After         []htmlLine
}

type htmlStep struct {
	Number int
	Title  string
	Lines  []htmlLine
	Blocks []htmlBlock
	Feeds  []htmlFeed
	After  []htmlLine
}

type htmlReport struct {
	CVE            string
	Image          string
	Current        feedDecision
	Legacy         feedDecision
	CurrentClass   string
	LegacyClass    string
	OldFeedURL     string
	NewFeedURL     string
	HasConclusions bool
	Documents      []embeddedDocument
	Steps          []htmlStep
}

type embeddedDocument struct {
	Name, Source, Filename, GzipFilename, CapturedAt, SHA256 string
	Feed                                                     string
	OriginalSize, CompressedSize                             int
	GzipURL                                                  template.URL
	ID                                                       string
}

func prepareEmbeddedDocuments(documents []capturedDocument) ([]embeddedDocument, error) {
	embedded := make([]embeddedDocument, 0, len(documents))
	for i, doc := range documents {
		feed := "shared"
		switch doc.Name {
		case "Old VEX feed":
			feed = "old"
		case "New VEX feed":
			feed = "new"
		}
		var compressed bytes.Buffer
		writer := gzip.NewWriter(&compressed)
		if _, err := writer.Write(doc.Data); err != nil {
			return nil, fmt.Errorf("compress %s: %w", doc.Name, err)
		}
		if err := writer.Close(); err != nil {
			return nil, fmt.Errorf("finish compressing %s: %w", doc.Name, err)
		}
		embedded = append(embedded, embeddedDocument{
			Name: doc.Name, Source: doc.Source, Filename: doc.Filename, GzipFilename: doc.Filename + ".gz",
			Feed:       feed,
			CapturedAt: doc.CapturedAt, SHA256: doc.SHA256, OriginalSize: len(doc.Data), CompressedSize: compressed.Len(),
			GzipURL: template.URL("data:application/gzip;base64," + base64.StdEncoding.EncodeToString(compressed.Bytes())),
			ID:      fmt.Sprintf("embedded-vex-%d", i),
		})
	}
	return embedded, nil
}

var stepHeading = regexp.MustCompile(`^Step ([1-9]) — (.+)$`)
var layerHeading = regexp.MustCompile(`^Layer [0-9]+ \(.+\):$`)
var olderLabelLayer = regexp.MustCompile(`^Layer ([0-9]+): (.+) is retained but unmatchable because layer ([0-9]+) is newer\.$`)
var olderDockerfileLayer = regexp.MustCompile(`^Legacy Dockerfile from layer ([0-9]+) is unmatchable because layer ([0-9]+) has newer RHCC repository content\.$`)

func isDirectValue(label string) bool {
	switch label {
	case "Image", "Image name", "Image CPE", "Source", "Document source", "Name", "Arch", "CPE", "Created", "Version",
		"Selected", "Skipped", "Archive entry", "Selected legacy Dockerfile", "Skipped legacy Dockerfile", "Component",
		"Candidate name", "Advisory CPE", "Name from PURL", "PURL", "Component name", "Product CPE",
		"Repository CPE", "Repository name", "Mapping", "Mapping SHA-256", "Name label", "Image repository", "Fixed version", "CSAF status IDs", "affected", "not affected":
		return true
	default:
		return false
	}
}

func formatLine(raw string) htmlLine {
	line := htmlLine{Text: strings.TrimSpace(raw), Depth: (len(raw) - len(strings.TrimLeft(raw, " "))) / 2}
	switch {
	case strings.HasPrefix(line.Text, "MATCH: "):
		line.Text = strings.TrimPrefix(line.Text, "MATCH: ")
		line.Badge, line.BadgeClass = "MATCH", "match"
	case strings.HasPrefix(line.Text, "SKIP: "):
		line.Text = strings.TrimPrefix(line.Text, "SKIP: ")
		line.Badge, line.BadgeClass = "SKIP", "skip"
	case strings.HasPrefix(line.Text, "Conclusion:"):
		line.Kind = "conclusion"
	}
	if at := strings.Index(line.Text, ": "); at > 0 && at <= 32 && !strings.ContainsAny(line.Text[:at], "/.") {
		line.Label, line.Value = line.Text[:at], strings.TrimSpace(line.Text[at+2:])
		line.Code = isDirectValue(line.Label)
		if line.Label == "Document source" {
			if source, err := url.Parse(line.Value); err == nil && (source.Scheme == "https" || source.Scheme == "http") && source.Host != "" {
				line.Link = line.Value
			}
		}
	} else if strings.HasPrefix(line.Text, "https://") || strings.HasPrefix(line.Text, "http://") {
		line.Code = true
	}
	formatInlineValues(&line)
	return line
}

func formatInlineValues(line *htmlLine) {
	if body, ok := strings.CutPrefix(line.Text, "Pull "); ok {
		if body, ok = strings.CutSuffix(body, " with skopeo."); ok {
			if at := strings.LastIndex(body, " for "); at >= 0 {
				line.Parts = []htmlPart{{Text: "Pull "}, {Text: body[:at], Code: true}, {Text: " for "}, {Text: body[at+5:], Code: true}, {Text: " with skopeo."}}
				return
			}
		}
	}
	if body, ok := strings.CutPrefix(line.Text, "Read local docker archive "); ok {
		if path, ok := strings.CutSuffix(body, "."); ok {
			line.Parts = []htmlPart{{Text: "Read local docker archive "}, {Text: path, Code: true}, {Text: "."}}
			return
		}
	}
	if match := olderLabelLayer.FindStringSubmatch(line.Text); match != nil {
		line.Label, line.Value = "", ""
		line.Parts = []htmlPart{{Text: "Layer "}, {Text: match[1], Code: true}, {Text: ": "}, {Text: match[2], Code: true}, {Text: " is retained but unmatchable because layer "}, {Text: match[3], Code: true}, {Text: " is newer."}}
		return
	}
	if match := olderDockerfileLayer.FindStringSubmatch(line.Text); match != nil {
		line.Parts = []htmlPart{{Text: "Legacy Dockerfile from layer "}, {Text: match[1], Code: true}, {Text: " is unmatchable because layer "}, {Text: match[2], Code: true}, {Text: " has newer RHCC repository content."}}
		return
	}
	if line.Label == "Matching layer" {
		number, detail, _ := strings.Cut(line.Value, " ")
		if _, err := strconv.Atoi(number); err == nil {
			line.Parts = []htmlPart{{Text: number, Code: true}}
			if detail != "" {
				line.Parts = append(line.Parts, htmlPart{Text: " " + detail})
			}
		}
		return
	}
	if line.Label == "Identity" {
		for _, name := range []string{"labels.json", "legacy Dockerfile"} {
			if line.Value == name {
				line.Parts = []htmlPart{{Text: name, Code: true}}
				return
			}
			if rest, ok := strings.CutPrefix(line.Value, name+": "); ok {
				line.Parts = []htmlPart{{Text: name, Code: true}, {Text: ": " + rest}}
				return
			}
		}
	}
}

func organizeStep(step *htmlStep) {
	lines := step.Lines
	step.Lines = nil
	var feed *htmlFeed
	var activeItem *htmlItem
	for _, line := range lines {
		if step.Number == 2 && layerHeading.MatchString(line.Text) {
			step.Blocks = append(step.Blocks, htmlBlock{Heading: line})
			continue
		}
		if step.Number == 2 && len(step.Blocks) > 0 && line.Depth >= 2 {
			last := &step.Blocks[len(step.Blocks)-1]
			last.Lines = append(last.Lines, line)
			continue
		}
		if step.Number == 2 && len(step.Blocks) > 0 {
			step.After = append(step.After, line)
			continue
		}
		if step.Number >= 4 {
			for _, name := range []string{"Old VEX feed", "New VEX feed"} {
				if line.Text == name || strings.HasPrefix(line.Text, name+": ") {
					summary := strings.TrimPrefix(line.Text, name+": ")
					if summary == name {
						summary = ""
					}
					step.Feeds = append(step.Feeds, htmlFeed{Name: name, Summary: summary})
					feed = &step.Feeds[len(step.Feeds)-1]
					activeItem = nil
					goto next
				}
			}
		}
		if feed != nil {
			if step.Number >= 5 && step.Number <= 8 && line.Label == "Identity" {
				feed.Identity = line.Value
				continue
			}
			if step.Number == 4 && line.Depth >= 2 && line.Label == "" {
				line.Code = true
			}
			if line.Label == "Candidate name" || line.Label == "Advisory CPE" {
				feed.Values = append(feed.Values, line)
			} else if line.Badge != "" {
				if step.Number == 8 && line.Badge == "SKIP" {
					feed.Skipped = append(feed.Skipped, htmlItem{Heading: line})
					activeItem = &feed.Skipped[len(feed.Skipped)-1]
				} else {
					feed.Items = append(feed.Items, htmlItem{Heading: line})
					activeItem = &feed.Items[len(feed.Items)-1]
				}
			} else if line.Depth >= 3 && activeItem != nil {
				activeItem.Details = append(activeItem.Details, line)
			} else if len(feed.Items)+len(feed.Skipped) > 0 {
				activeItem = nil
				feed.After = append(feed.After, line)
			} else {
				feed.Lines = append(feed.Lines, line)
			}
		} else {
			step.Lines = append(step.Lines, line)
		}
	next:
	}
	collapseEvidence := false
	for _, feed := range step.Feeds {
		if len(feed.Items) > 10 {
			collapseEvidence = true
			break
		}
	}
	for i := range step.Feeds {
		step.Feeds[i].ShowEvidence = step.Number >= 5 && step.Number <= 8
		step.Feeds[i].CollapseItems = collapseEvidence
	}
}

func renderHTML(out io.Writer, o options, trace string) error {
	var summary walkSummary
	summary.markImageIncomplete("Incomplete", "The walkthrough did not reach feed matching.")
	return renderHTMLWithSummary(out, o, summary, trace)
}

func verdictClass(label string) string {
	switch label {
	case "Affected":
		return "affected"
	case "Not affected":
		return "not-affected"
	case "Conflicting evidence":
		return "conflict"
	default:
		return "unknown"
	}
}

func renderHTMLWithSummary(out io.Writer, o options, summary walkSummary, trace string) error {
	image := o.image
	if image == "" {
		image = o.archive
	}
	current, legacy := summary.currentDecision(), summary.legacyDecision()
	page := htmlReport{CVE: strings.ToUpper(strings.TrimSpace(o.cve)), Image: image, Current: current, Legacy: legacy, CurrentClass: verdictClass(current.Label), LegacyClass: verdictClass(legacy.Label)}
	if cvePattern.MatchString(page.CVE) {
		page.OldFeedURL = redHatVEXDocumentURL(page.CVE, "vex")
		page.NewFeedURL = redHatVEXDocumentURL(page.CVE, "vex-feed")
	}
	if o.documents != nil {
		var err error
		page.Documents, err = prepareEmbeddedDocuments(*o.documents)
		if err != nil {
			return err
		}
	}
	for _, raw := range strings.Split(trace, "\n") {
		if match := stepHeading.FindStringSubmatch(raw); match != nil {
			number, _ := strconv.Atoi(match[1])
			page.Steps = append(page.Steps, htmlStep{Number: number, Title: match[2]})
			continue
		}
		if len(page.Steps) == 0 || strings.TrimSpace(raw) == "" {
			continue
		}
		last := &page.Steps[len(page.Steps)-1]
		last.Lines = append(last.Lines, formatLine(raw))
	}
	if len(page.Steps) == 0 {
		return fmt.Errorf("could not render HTML: no walkthrough steps")
	}
	for i := range page.Steps {
		organizeStep(&page.Steps[i])
		if page.Steps[i].Number == 9 {
			page.HasConclusions = true
		}
	}
	return htmlPage.Execute(out, page)
}

var htmlPage = template.Must(template.New("walkthrough").Parse(`<!doctype html>
<html lang="en" data-feed-view="both">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{.CVE}} | VEX walkthrough</title>
  <style>
    :root { color-scheme: light; --ink:#172d34; --muted:#52666d; --line:#d6e1df; --paper:#f4f7f5; --white:#fff; --teal:#087366; --teal-soft:#e2f2ec; --amber:#8a5913; --amber-soft:#fff2d8; }
    * { box-sizing:border-box; }
    html { scroll-behavior:smooth; }
    body { margin:0; background:var(--paper); color:var(--ink); font:15px/1.55 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
    .masthead { background:linear-gradient(125deg,#12343b,#15594f); color:white; padding:34px max(24px,calc((100vw - 1420px)/2)); }
    .eyebrow { margin:0 0 8px; color:#a9e0cf; font-size:12px; font-weight:700; letter-spacing:.13em; text-transform:uppercase; }
    h1 { margin:0 0 10px; font-size:clamp(28px,4vw,42px); letter-spacing:-.035em; line-height:1.15; }
    .source { margin:0; color:#d3e7e2; overflow-wrap:anywhere; font-family:ui-monospace,SFMono-Regular,Consolas,monospace; font-size:13px; }
    .feed-guide { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:10px 20px; max-width:1120px; margin-top:18px; color:#e1f1ed; font-size:13px; }
    .feed-guide p { margin:0; }
    .feed-guide a { color:white; font-weight:750; text-underline-offset:3px; }
    .feed-guide-note { grid-column:1 / -1; color:#c5e2da; font-size:12px; }
    .decision-grid { display:grid; grid-template-columns:minmax(0,1fr) minmax(0,1.25fr); gap:14px; max-width:1120px; margin-top:24px; }
    .decision-card { padding:17px 20px; border-radius:11px; background:white; color:var(--ink); border-left:5px solid #7d8e91; box-shadow:0 6px 18px #092c2a24; }
    .decision-card.affected { border-left-color:#b33b32; }
    .decision-card.not-affected { border-left-color:var(--teal); }
    .decision-card.conflict { border-left-color:#b67716; }
    .decision-card .decision-source { margin:0 0 3px; color:var(--muted); font-size:12px; font-weight:800; letter-spacing:.07em; text-transform:uppercase; }
    .decision-card strong { display:block; font-size:clamp(22px,2.5vw,30px); line-height:1.2; }
    .decision-card .decision-reason { margin:8px 0 0; font-size:13px; color:#42565b; }
    .decision-card a { display:inline-block; margin-top:10px; color:#075d52; font-size:13px; font-weight:750; text-underline-offset:3px; }
    .document-grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:14px; }
    .document-card { min-width:0; padding:16px; border:1px solid var(--line); border-radius:9px; background:#fbfdfc; }
    .document-card h3 { margin:0 0 10px; font-size:16px; }
    .document-card p { margin:6px 0; overflow-wrap:anywhere; }
    .document-card code { overflow-wrap:anywhere; font-size:12px; }
    .document-actions { display:flex; flex-wrap:wrap; align-items:center; gap:9px; margin-top:14px; }
    .document-actions a,.document-actions button { padding:8px 11px; border:1px solid var(--teal); border-radius:6px; background:var(--teal); color:white; font:inherit; font-size:13px; font-weight:700; text-decoration:none; cursor:pointer; }
    .document-actions a { background:white; color:#075d52; }
    .document-actions button:disabled { opacity:.6; cursor:wait; }
    .download-status { width:100%; color:var(--muted); font-size:12px; }
    .shell { max-width:1420px; margin:0 auto; padding:28px 24px 60px; display:grid; grid-template-columns:230px minmax(0,1fr); gap:28px; }
    nav { align-self:start; position:sticky; top:20px; z-index:10; max-height:calc(100vh - 40px); overflow:auto; background:var(--white); border:1px solid var(--line); border-radius:12px; padding:18px; }
    nav strong { display:block; margin:0 0 10px; color:var(--muted); font-size:12px; letter-spacing:.09em; text-transform:uppercase; }
    nav a { display:block; padding:7px 9px; border-radius:6px; color:var(--ink); text-decoration:none; font-size:13px; }
    nav a:hover,nav a:focus-visible { background:var(--teal-soft); color:#075d52; }
    .feed-controls { position:sticky; top:-18px; z-index:1; margin:-18px -18px 16px; padding:18px 18px 14px; background:var(--white); border-bottom:1px solid var(--line); }
    .feed-controls .control-title { display:block; margin:0 0 8px; color:var(--muted); font-size:12px; font-weight:800; letter-spacing:.07em; text-transform:uppercase; }
    .feed-toggle { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:4px; }
    .feed-toggle button { min-width:0; padding:7px 3px; border:1px solid var(--line); border-radius:6px; background:white; color:var(--ink); font:inherit; font-size:12px; font-weight:700; cursor:pointer; }
    .feed-toggle button[aria-pressed="true"] { border-color:var(--teal); background:var(--teal-soft); color:#075d52; }
    .feed-toggle button:focus-visible { outline:2px solid var(--teal); outline-offset:2px; }
    .mobile-step-links { display:none; }
    .mobile-step-links summary { cursor:pointer; padding:6px 9px; font-size:13px; font-weight:700; }
    html[data-feed-view="old"] [data-feed="new"],html[data-feed-view="new"] [data-feed="old"] { display:none !important; }
    html[data-feed-view="old"] .decision-grid,html[data-feed-view="new"] .decision-grid,html[data-feed-view="old"] .feed-grid,html[data-feed-view="new"] .feed-grid { grid-template-columns:minmax(0,1fr); }
    main { min-width:0; }
    section { background:var(--white); border:1px solid var(--line); border-radius:13px; margin:0 0 20px; padding:24px 28px; box-shadow:0 2px 12px #173b3510; scroll-margin-top:20px; }
    section.summary { border-color:#a1cfc1; background:linear-gradient(180deg,#f8fdfa,#fff 80%); }
    h2 { display:flex; align-items:center; gap:12px; margin:0 0 18px; font-size:20px; letter-spacing:-.02em; }
    .number { display:inline-flex; align-items:center; justify-content:center; width:34px; height:34px; flex:none; border-radius:9px; background:var(--teal-soft); color:var(--teal); font-size:14px; font-weight:800; }
    .entries { display:grid; gap:7px; min-width:0; }
    .entry { margin:0; overflow-wrap:anywhere; }
    .entry.pair { display:grid; grid-template-columns:minmax(105px,145px) minmax(0,1fr); gap:6px 14px; align-items:baseline; }
    .entry-label { color:var(--muted); font-size:13px; font-weight:700; }
    .entry-value { min-width:0; }
    .entry-code { display:inline-block; max-width:100%; padding:3px 7px; border:1px solid #dce6e4; border-radius:5px; background:#f3f7f6; color:#20373d; font:13px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace; white-space:pre-wrap; overflow-wrap:anywhere; }
    .entry-link { min-width:0; overflow-wrap:anywhere; text-underline-offset:3px; }
    .entry-link .entry-code { color:#075d52; text-decoration:underline; }
    .entry.conclusion { margin:8px 0; padding:11px 13px; border-left:3px solid var(--teal); border-radius:5px; background:var(--teal-soft); font-weight:650; }
    .entry.conclusion .entry-label { color:#075d52; }
    .layer-grid { display:grid; grid-template-columns:minmax(0,1fr); gap:12px; margin:14px 0; }
    .layer-card,.feed-card,.evidence-card { min-width:0; border:1px solid var(--line); border-radius:10px; background:#fff; }
    .layer-card { padding:16px; background:#fafcfb; }
    .layer-card h3,.feed-card h3 { margin:0 0 12px; font-size:16px; line-height:1.35; overflow-wrap:anywhere; }
    .layer-card h3 { font-family:ui-monospace,SFMono-Regular,Consolas,monospace; }
    .feed-grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:14px; margin:16px 0 0; align-items:start; }
    .feed-card { padding:18px; background:#fbfdfc; }
    .feed-grid > :only-child { grid-column:1 / -1; }
    .feed-card h3 { color:#075d52; }
    .feed-identity { margin:-3px 0 12px; color:var(--muted); font-size:12px; font-weight:750; }
    .feed-summary { margin:-3px 0 15px; padding:9px 12px; border-radius:7px; background:var(--teal-soft); font-weight:650; }
    .value-list { margin:12px 0; border:1px solid var(--line); border-radius:8px; background:white; }
    .value-list summary { cursor:pointer; padding:9px 12px; font-size:13px; font-weight:750; color:#075d52; }
    .value-list[open] summary { border-bottom:1px solid var(--line); }
    .value-list .entries { padding:10px 12px 12px; }
    .value-list .evidence-list { padding:0 12px 12px; }
    .empty-evidence { margin:0; padding:10px 12px 12px; color:var(--muted); font-size:13px; }
    .evidence-list { display:grid; gap:10px; margin:14px 0 0; }
    .evidence-card { padding:12px 13px; }
    .evidence-heading { display:flex; align-items:flex-start; gap:8px; margin:0 0 10px; font-weight:700; overflow-wrap:anywhere; }
    .evidence-heading > span:last-child { font-family:ui-monospace,SFMono-Regular,Consolas,monospace; font-size:13px; }
    .evidence-card .entries { padding-left:0; font-size:14px; }
    .after { margin-top:16px; padding-top:14px; border-top:1px solid var(--line); }
    .badge { display:inline-block; min-width:58px; margin-right:8px; padding:2px 6px; border-radius:4px; font-size:11px; font-weight:800; letter-spacing:.04em; text-align:center; vertical-align:middle; }
    .badge-match { background:var(--teal-soft); color:#075d52; }
    .badge-skip { background:var(--amber-soft); color:var(--amber); }
    @media (max-width:1080px) { .feed-grid { grid-template-columns:1fr; } }
    @media (max-width:850px) { .shell { display:block; padding:20px 14px; } nav { top:0; max-height:70vh; margin-bottom:20px; padding:12px; box-shadow:0 5px 15px #173b3520; } .feed-controls { top:-12px; margin:-12px -12px 8px; padding:10px 12px; } nav > strong,nav > .step-links { display:none; } .mobile-step-links { display:block; } section { padding:20px 17px; } .decision-grid,.document-grid,.feed-guide { grid-template-columns:1fr; } .feed-guide-note { grid-column:auto; } }
    @media (max-width:520px) { .entry.pair { grid-template-columns:1fr; gap:0; } .feed-card { padding:14px; } }
    @media print { body { background:white; color:black; } .masthead { background:white; color:black; padding:0 0 18px; } .eyebrow,.source { color:#333; } .shell { display:block; padding:0; } nav { display:none; } section { box-shadow:none; break-inside:auto; margin:0 0 14px; } .feed-grid { grid-template-columns:repeat(2,minmax(0,1fr)); } .feed-card,.evidence-card,.layer-card,.decision-card { break-inside:avoid; } .value-list:not([open]) > .entries { display:grid; } }
  </style>
</head>
<body>
  <header class="masthead">
    <p class="eyebrow">OCI image / Red Hat VEX</p>
    <h1>{{.CVE}} walkthrough</h1>
    <p class="source">Image: {{.Image}}</p>
    <div class="feed-guide" aria-label="VEX feed sources">
      <p data-feed="old"><a href="{{if .OldFeedURL}}{{.OldFeedURL}}{{else}}https://security.access.redhat.com/data/csaf/v2/vex/{{end}}">Old VEX feed</a> uses Red Hat's <code>/vex/</code> path; shown for comparison.</p>
      <p data-feed="new"><a href="{{if .NewFeedURL}}{{.NewFeedURL}}{{else}}https://security.access.redhat.com/data/csaf/v2/vex-feed/{{end}}">New VEX feed</a> uses Red Hat's <code>/vex-feed/</code> path; used by the Claircore updater.</p>
      <p class="feed-guide-note">Step 4 shows the document source actually loaded for this run, including any local override.</p>
    </div>
    <div class="decision-grid" aria-label="VEX conclusions">
      <div class="decision-card {{.LegacyClass}}" data-feed="old"><p class="decision-source">Old VEX feed</p><strong>{{.Legacy.Label}}</strong><p class="decision-reason">{{.Legacy.Reason}}</p>{{if .HasConclusions}}<a href="#step-7">Status relationships</a> · <a href="#step-8">Matched assertions</a> · <a href="#step-9">Conclusions</a>{{end}}</div>
      <div class="decision-card {{.CurrentClass}}" data-feed="new"><p class="decision-source">New VEX feed · Claircore source</p><strong>{{.Current.Label}}</strong><p class="decision-reason">{{.Current.Reason}}</p>{{if .HasConclusions}}<a href="#step-7">Status relationships</a> · <a href="#step-8">Matched assertions</a> · <a href="#step-9">Conclusions</a>{{end}}</div>
    </div>
  </header>
  <div class="shell">
    <nav aria-label="Walkthrough controls and steps">
      <div class="feed-controls"><span class="control-title">Show VEX feed</span><div class="feed-toggle" role="group" aria-label="Visible VEX results">
        <button type="button" data-feed-choice="both" aria-pressed="true">Both</button>
        <button type="button" data-feed-choice="old" aria-pressed="false" aria-label="Show old VEX feed results">Old</button>
        <button type="button" data-feed-choice="new" aria-pressed="false" aria-label="Show new VEX feed results">New</button>
      </div></div>
      <strong>Steps</strong><div class="step-links">{{if .Documents}}<a href="#captured-documents">Captured source documents</a>{{end}}{{range .Steps}}<a href="#step-{{.Number}}">{{.Number}}. {{if eq .Number 9}}Conclusions{{else}}{{.Title}}{{end}}</a>{{end}}</div>
      <details class="mobile-step-links"><summary>Jump to a step</summary>{{if .Documents}}<a href="#captured-documents">Captured source documents</a>{{end}}{{range .Steps}}<a href="#step-{{.Number}}">{{.Number}}. {{if eq .Number 9}}Conclusions{{else}}{{.Title}}{{end}}</a>{{end}}</details>
    </nav>
    <main>
      {{if .Documents}}<section id="captured-documents" aria-labelledby="captured-documents-title">
        <h2 id="captured-documents-title">Captured source documents</h2>
        <p>These are the exact document and mapping bytes loaded for this walkthrough. The SHA-256 checksum applies to the original JSON.</p>
        <div class="document-grid">{{range .Documents}}<article class="document-card" data-feed="{{.Feed}}">
          <h3>{{.Name}}</h3>
          <p><strong>Source:</strong> <code class="entry-code">{{.Source}}</code></p>
          <p><strong>Captured:</strong> <code class="entry-code">{{.CapturedAt}}</code> · <code class="entry-code">{{.OriginalSize}}</code> bytes</p>
          <p><strong>SHA-256:</strong> <code>{{.SHA256}}</code></p>
          <div class="document-actions">
            <button type="button" data-download-json data-source-id="{{.ID}}" data-filename="{{.Filename}}">Download JSON</button>
            <a id="{{.ID}}" href="{{.GzipURL}}" download="{{.GzipFilename}}">Download compressed copy (.json.gz)</a>
            <span class="download-status" role="status"></span>
          </div>
        </article>{{end}}</div>
      </section>{{end}}
      {{range .Steps}}
      <section id="step-{{.Number}}"{{if eq .Number 9}} class="summary"{{end}} aria-labelledby="step-title-{{.Number}}">
        <h2 id="step-title-{{.Number}}"><span class="number">{{.Number}}</span>{{.Title}}</h2>
        {{if .Lines}}<div class="entries">{{range .Lines}}{{template "entry" .}}{{end}}</div>{{end}}
        {{if .Blocks}}<div class="layer-grid">{{range .Blocks}}<article class="layer-card"><h3>{{.Heading.Text}}</h3><div class="entries">{{range .Lines}}{{template "entry" .}}{{end}}</div></article>{{end}}</div>{{end}}
        {{if .Feeds}}<div class="feed-grid">
          {{range .Feeds}}<article class="feed-card" data-feed="{{if eq .Name "Old VEX feed"}}old{{else}}new{{end}}">
            <h3>{{.Name}}</h3>{{if .Identity}}<p class="feed-identity">Identity: <code class="entry-code">{{.Identity}}</code></p>{{end}}
            {{if .Summary}}<p class="feed-summary">{{.Summary}}</p>{{end}}
            {{if .Lines}}<div class="entries">{{range .Lines}}{{template "entry" .}}{{end}}</div>{{end}}
            {{if .Values}}<details class="value-list"><summary>Compared values ({{len .Values}})</summary><div class="entries">{{range .Values}}{{template "entry" .}}{{end}}</div></details>{{end}}
            {{if .ShowEvidence}}<details class="value-list evidence-group"{{if not .CollapseItems}} open{{end}}><summary>Evidence records ({{len .Items}})</summary>{{if .Items}}<div class="evidence-list">{{range .Items}}{{template "evidence" .}}{{end}}</div>{{else}}<p class="empty-evidence">No detailed records to show.</p>{{end}}</details>{{end}}
            {{if .Skipped}}<details class="value-list"><summary>Non-matching Claircore assertions ({{len .Skipped}})</summary><div class="evidence-list">{{range .Skipped}}{{template "evidence" .}}{{end}}</div></details>{{end}}
            {{if .After}}<div class="after entries">{{range .After}}{{template "entry" .}}{{end}}</div>{{end}}
          </article>{{end}}
        </div>{{end}}
        {{if .After}}<div class="after entries">{{range .After}}{{template "entry" .}}{{end}}</div>{{end}}
      </section>{{end}}
    </main>
  </div>
<script>
  const feedChoices = document.querySelectorAll('[data-feed-choice]');
  feedChoices.forEach(button => button.addEventListener('click', () => {
    document.documentElement.dataset.feedView = button.dataset.feedChoice;
    feedChoices.forEach(choice => choice.setAttribute('aria-pressed', String(choice === button)));
  }));
  document.querySelectorAll('[data-download-json]').forEach(button => {
    if (!('DecompressionStream' in window)) {
      button.hidden = true;
      return;
    }
    button.addEventListener('click', async () => {
      const status = button.parentElement.querySelector('.download-status');
      button.disabled = true;
      status.textContent = 'Preparing JSON download…';
      try {
        const source = document.getElementById(button.dataset.sourceId);
        const encoded = source.getAttribute('href').split(',', 2)[1];
        const chunks = [];
        for (let offset = 0; offset < encoded.length; offset += 32768) {
          const binary = atob(encoded.slice(offset, offset + 32768));
          const bytes = new Uint8Array(binary.length);
          for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
          chunks.push(bytes);
        }
        const gzipBlob = new Blob(chunks, {type: 'application/gzip'});
        const jsonBlob = await new Response(gzipBlob.stream().pipeThrough(new DecompressionStream('gzip'))).blob();
        const url = URL.createObjectURL(new Blob([jsonBlob], {type: 'application/json'}));
        const link = document.createElement('a');
        link.href = url;
        link.download = button.dataset.filename;
        document.body.appendChild(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 60000);
        status.textContent = 'JSON download started.';
      } catch (error) {
        status.textContent = 'JSON download failed. Use the compressed copy instead.';
      } finally {
        button.disabled = false;
      }
    });
  });
</script>
</body>
</html>
{{define "parts"}}{{range .}}{{if .Code}}<code class="entry-code">{{.Text}}</code>{{else}}{{.Text}}{{end}}{{end}}{{end}}
{{define "entry"}}<div class="entry {{if .Label}}pair{{end}} {{.Kind}}">{{if .Label}}<span class="entry-label">{{.Label}}</span>{{if .Parts}}<span class="entry-value">{{template "parts" .Parts}}</span>{{else if .Link}}<a class="entry-link" href="{{.Link}}"><code class="entry-code">{{.Value}}</code></a>{{else if .Code}}<code class="entry-code">{{.Value}}</code>{{else}}<span class="entry-value">{{.Value}}</span>{{end}}{{else}}{{if .Badge}}<span class="badge badge-{{.BadgeClass}}">{{.Badge}}</span>{{end}}{{if .Parts}}<span>{{template "parts" .Parts}}</span>{{else if .Code}}<code class="entry-code">{{.Text}}</code>{{else}}<span>{{.Text}}</span>{{end}}{{end}}</div>{{end}}
{{define "evidence"}}<article class="evidence-card"><div class="evidence-heading"><span class="badge badge-{{.Heading.BadgeClass}}">{{.Heading.Badge}}</span><span>{{.Heading.Text}}</span></div>{{if .Details}}<div class="entries">{{range .Details}}{{template "entry" .}}{{end}}</div>{{end}}</article>{{end}}
`))
