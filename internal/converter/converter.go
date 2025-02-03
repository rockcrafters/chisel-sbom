package converter

import (
	"os"
	"reflect"
	"strings"

	"github.com/canonical/chisel/public/jsonwall"
	"github.com/canonical/chisel/public/manifest"
	"github.com/klauspost/compress/zstd"
	"github.com/rockcrafters/chisel-sbom/internal/builder"
	"github.com/spdx/tools-golang/spdx"
)

type ManifestEntry struct {
	Kind string `json:"kind"`
}

type ManifestData struct {
	Packages []manifest.Package
	Slices   []manifest.Slice
	Paths    []manifest.Path
	Content  []manifest.Content
}

var ManifestStructs = map[string]reflect.Type{
	"package": reflect.TypeOf(manifest.Package{}),
	"slice":   reflect.TypeOf(manifest.Slice{}),
	"path":    reflect.TypeOf(manifest.Path{}),
	"content": reflect.TypeOf(manifest.Content{}),
}

var manifestData = ManifestData{
	Packages: []manifest.Package{},
	Slices:   []manifest.Slice{},
	Paths:    []manifest.Path{},
	Content:  []manifest.Content{},
}

// Convert converts a JSONWall to an SPDX document.
func Convert(path string) (*spdx.Document, error) {
	fileReader, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fileReader.Close()
	zstdReader, err := zstd.NewReader(fileReader)
	if err != nil {
		return nil, err
	}
	defer zstdReader.Close()
	db, err := jsonwall.ReadDB(zstdReader)

	iter, err := db.Iterate(nil)
	if err != nil {
		return nil, err
	}
	for iter.Next() {
		var entry ManifestEntry
		if err := iter.Get(&entry); err != nil {
			return nil, err
		}
		var value = unmarshalManifestEntry(entry.Kind)
		if err := iter.Get(&value); err != nil {
			return nil, err
		}
		manifestData.append(entry.Kind, value)
	}

	sliceInfos := manifestData.processSlices()
	packageInfos := manifestData.processPackages()
	pathInfos := manifestData.processPaths()

	doc, err := builder.BuildSPDXDocument("test", &sliceInfos, &packageInfos, &pathInfos)
	if err != nil {
		return nil, err
	}

	return doc, nil
}

func (md *ManifestData) processSlices() []builder.SliceInfo {
	var sliceInfos []builder.SliceInfo
	for _, s := range md.Slices {
		var sliceInfo builder.SliceInfo
		sliceInfo.Name = s.Name
		sliceInfos = append(sliceInfos, sliceInfo)
	}
	return sliceInfos
}

func (md *ManifestData) processPackages() []builder.PackageInfo {
	var packageInfos []builder.PackageInfo
	for _, p := range md.Packages {
		var packageInfo builder.PackageInfo
		packageInfo.Name = p.Name
		packageInfo.Version = p.Version
		packageInfo.SHA256 = p.Digest
		packageInfos = append(packageInfos, packageInfo)
	}
	return packageInfos
}

func (md *ManifestData) processPaths() []builder.PathInfo {
	var pathInfos []builder.PathInfo
	for _, p := range md.Paths {
		if strings.HasSuffix(p.Path, "/") {
			continue
		}
		var pathInfo builder.PathInfo
		pathInfo.Path = p.Path
		pathInfo.Mode = p.Mode
		pathInfo.Slices = p.Slices
		sha256 := p.SHA256
		if p.FinalSHA256 != "" {
			sha256 = p.FinalSHA256
		}
		pathInfo.SHA256 = sha256
		pathInfos = append(pathInfos, pathInfo)
	}
	return pathInfos
}

func unmarshalManifestEntry(typeName string) interface{} {
	if typ, found := ManifestStructs[typeName]; found {
		return reflect.New(typ).Interface()
	}
	return nil
}

func (md *ManifestData) append(kind string, value interface{}) {
	switch kind {
	case "package":
		md.Packages = append(md.Packages, *value.(*manifest.Package))
	case "slice":
		md.Slices = append(md.Slices, *value.(*manifest.Slice))
	case "path":
		md.Paths = append(md.Paths, *value.(*manifest.Path))
	case "content":
		md.Content = append(md.Content, *value.(*manifest.Content))
	}
}
