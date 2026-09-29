package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

var resultColumns = []string{"detected_name", "detected_cpe", "old_vex_conclusion", "new_vex_conclusion", "processing_error"}

type batchKey struct{ image, cve string }
type batchResult struct {
	summary walkSummary
	err     error
}
type archiveResult struct {
	path string
	err  error
}

func runBatchCSV(ctx context.Context, o options, out io.Writer) error {
	if o.image != "" || o.archive != "" || o.cve != "" {
		return fmt.Errorf("--input-csv supplies images and CVEs; omit --image, --archive, and --cve")
	}
	f, err := os.Open(o.inputCSV)
	if err != nil {
		return err
	}
	defer f.Close()
	records, err := csv.NewReader(f).ReadAll()
	if err != nil {
		return fmt.Errorf("read input CSV: %w", err)
	}
	if len(records) == 0 {
		return fmt.Errorf("input CSV has no header")
	}
	header := records[0]
	header[0] = strings.TrimPrefix(header[0], "\ufeff")
	imageIndex, err := columnIndex(header, o.imageColumn)
	if err != nil {
		return fmt.Errorf("image column: %w", err)
	}
	cveIndex, err := columnIndex(header, o.cveColumn)
	if err != nil {
		return fmt.Errorf("CVE column: %w", err)
	}
	if imageIndex == cveIndex {
		return fmt.Errorf("image and CVE columns must differ")
	}
	keys := make([]batchKey, len(records)-1)
	remainingByImage := map[string]int{}
	seenPairs := map[batchKey]bool{}
	for i, row := range records[1:] {
		image, cve := strings.TrimSpace(row[imageIndex]), strings.ToUpper(strings.TrimSpace(row[cveIndex]))
		key := batchKey{image, cve}
		keys[i] = key
		if image != "" && cvePattern.MatchString(cve) && !seenPairs[key] {
			seenPairs[key] = true
			remainingByImage[image]++
		}
	}
	resultIndexes := make([]int, len(resultColumns))
	for i, name := range resultColumns {
		index := -1
		for j, heading := range header {
			if strings.EqualFold(heading, name) {
				if index >= 0 {
					return fmt.Errorf("duplicate output column %q", name)
				}
				index = j
			}
		}
		if index < 0 {
			index = len(header)
			header = append(header, name)
		}
		resultIndexes[i] = index
	}
	w := csv.NewWriter(out)
	if err := writeBatchRecord(w, header); err != nil {
		return err
	}

	tempDir, err := os.MkdirTemp("", "ocivexwalk-batch-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)
	archives := map[string]archiveResult{}
	results := map[batchKey]batchResult{}
	o.documentCache = map[string][]byte{}
	processedImages, totalImages := 0, len(remainingByImage)
	batchProgress(o.progress, processedImages, totalImages, "")
	failedRows := 0
	for i, key := range keys {
		result := batchResult{}
		if key.image == "" || !cvePattern.MatchString(key.cve) {
			result.err = fmt.Errorf("nonempty image and CVE such as CVE-2024-24786 required")
		} else if cached, found := results[key]; found {
			result = cached
		} else {
			batchProgress(o.progress, processedImages, totalImages, fmt.Sprintf("processing %s for %s", key.image, key.cve))
			archive, cached := archives[key.image]
			if !cached {
				if strings.HasPrefix(key.image, "docker-archive:") {
					archive.path = strings.TrimPrefix(key.image, "docker-archive:")
					if archive.path == "" {
						archive.err = fmt.Errorf("empty docker-archive path")
					}
				} else {
					archive.path = filepath.Join(tempDir, fmt.Sprintf("image-%d.tar", len(archives)))
					args, err := skopeoCopyArgs(key.image, archive.path, o.platform)
					if err != nil {
						archive.err = err
					} else {
						cmd := exec.CommandContext(ctx, "skopeo", args...)
						var stderr bytes.Buffer
						progress := o.progress
						if progress == nil {
							progress = io.Discard
						}
						cmd.Stderr = io.MultiWriter(progress, &stderr)
						if err := o.progressTask(1, "Pulling image "+key.image, cmd.Run); err != nil {
							archive.err = fmt.Errorf("skopeo copy: %w", err)
							if detail := strings.TrimSpace(stderr.String()); detail != "" {
								archive.err = fmt.Errorf("%w: %s", archive.err, detail)
							}
						}
					}
				}
				archives[key.image] = archive
			}
			result.err = archive.err
			if result.err == nil {
				rowOptions := o
				rowOptions.image, rowOptions.archive, rowOptions.cve = "", archive.path, key.cve
				rowOptions.summary = &result.summary
				result.err = run(ctx, rowOptions, io.Discard)
			}
			results[key] = result
			remainingByImage[key.image]--
			if remainingByImage[key.image] == 0 {
				processedImages++
				batchProgress(o.progress, processedImages, totalImages, "")
			}
		}
		row := records[i+1]
		if len(row) < len(header) {
			row = append(row, make([]string, len(header)-len(row))...)
		}
		row[resultIndexes[0]] = result.summary.DetectedName
		row[resultIndexes[1]] = result.summary.DetectedCPE
		if result.err != nil {
			failedRows++
			row[resultIndexes[2]], row[resultIndexes[3]] = "", ""
			row[resultIndexes[4]] = result.err.Error()
			if o.progress != nil {
				fmt.Fprintf(o.progress, "CSV record %d failed: %v\n", i+2, result.err)
			}
		} else {
			row[resultIndexes[2]] = result.summary.legacyDecision().Label
			row[resultIndexes[3]] = result.summary.currentDecision().Label
			row[resultIndexes[4]] = ""
		}
		if err := writeBatchRecord(w, row); err != nil {
			return err
		}
	}
	if failedRows > 0 {
		return fmt.Errorf("%d of %d CSV records failed; see processing_error column", failedRows, len(keys))
	}
	return nil
}

func writeBatchRecord(w *csv.Writer, row []string) error {
	if err := w.Write(row); err != nil {
		return err
	}
	w.Flush()
	return w.Error()
}

func batchProgress(out io.Writer, processed, total int, activity string) {
	if out == nil {
		return
	}
	if activity != "" {
		fmt.Fprintf(out, "Images processed: %d/%d; %s\n", processed, total, activity)
		return
	}
	fmt.Fprintf(out, "Images processed: %d/%d\n", processed, total)
}

func columnIndex(header []string, spec string) (int, error) {
	index := -1
	for i, heading := range header {
		if strings.EqualFold(heading, spec) {
			if index >= 0 {
				return 0, fmt.Errorf("header %q is ambiguous", spec)
			}
			index = i
		}
	}
	if index >= 0 {
		return index, nil
	}
	if number, err := strconv.Atoi(spec); err == nil {
		if number >= 1 && number <= len(header) {
			return number - 1, nil
		}
		return 0, fmt.Errorf("column number %d is outside the CSV header", number)
	}
	index = 0
	for _, letter := range strings.ToUpper(spec) {
		if letter < 'A' || letter > 'Z' {
			return 0, fmt.Errorf("header %q not found", spec)
		}
		index = index*26 + int(letter-'A'+1)
	}
	if spec != "" && index <= len(header) {
		return index - 1, nil
	}
	return 0, fmt.Errorf("header %q not found", spec)
}
