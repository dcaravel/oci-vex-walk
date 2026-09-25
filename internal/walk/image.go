package walk

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
)

// File is a buildinfo file found in one image layer. Layer numbers start at zero.
type File struct {
	Layer int
	Path  string
	Data  []byte
}

type Layer struct {
	Number      int
	ArchivePath string
	Files       []File
}

type Image struct {
	Layers []Layer
}

type dockerManifest struct {
	Layers []string `json:"Layers"`
}

// ReadDockerArchive reads the single-platform docker-archive produced by
// skopeo copy or crane pull. It inspects each layer separately, as Claircore's
// RHCC scanners do; a flattened filesystem would hide older RHCC records.
func ReadDockerArchive(filename string) (*Image, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tr := tar.NewReader(f)
	var manifest []dockerManifest
	layers := map[string][]File{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("archive: %w", err)
		}
		name := strings.TrimPrefix(path.Clean(h.Name), "./")
		if name == "manifest.json" {
			b, err := io.ReadAll(io.LimitReader(tr, 16<<20))
			if err != nil {
				return nil, err
			}
			if err := json.Unmarshal(b, &manifest); err != nil {
				return nil, fmt.Errorf("manifest.json: %w", err)
			}
		} else if strings.HasSuffix(name, ".tar") || strings.HasSuffix(name, ".tar.gz") {
			files, err := readLayer(io.LimitReader(tr, h.Size))
			if err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			layers[name] = files
		}
	}
	if len(manifest) != 1 {
		return nil, fmt.Errorf("archive must contain one image manifest (got %d)", len(manifest))
	}
	image := &Image{}
	for i, name := range manifest[0].Layers {
		cleanName := strings.TrimPrefix(path.Clean(name), "./")
		files, ok := layers[cleanName]
		if !ok {
			return nil, fmt.Errorf("layer %d %q missing from archive", i, name)
		}
		for j := range files {
			files[j].Layer = i
		}
		image.Layers = append(image.Layers, Layer{Number: i, ArchivePath: cleanName, Files: files})
	}
	return image, nil
}

func readLayer(input io.Reader) ([]File, error) {
	br := bufio.NewReader(input)
	magic, _ := br.Peek(2)
	var r io.Reader = br
	if len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(r)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		r = gz
	}
	tr := tar.NewReader(r)
	files := map[string]File{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
			continue
		}
		name := strings.TrimPrefix(path.Clean(h.Name), "./")
		if name != "root/buildinfo/labels.json" && name != "usr/share/buildinfo/labels.json" && !strings.HasPrefix(name, "root/buildinfo/Dockerfile-") {
			continue
		}
		if h.Size > 8<<20 {
			return nil, fmt.Errorf("buildinfo file %q exceeds 8 MiB", name)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		files[name] = File{Path: name, Data: b}
	}
	out := make([]File, 0, len(files))
	for _, f := range files {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}
