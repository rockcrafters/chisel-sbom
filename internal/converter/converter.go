package converter

import (
	"fmt"
	"os"
	"strings"

	"github.com/canonical/chisel/public/jsonwall"
	"github.com/canonical/chisel/public/manifest"
	"github.com/klauspost/compress/zstd"
	"github.com/rockcrafters/chisel-sbom/internal/builder"
	"github.com/spdx/tools-golang/spdx"
)

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

	manifestData := &ManifestData{}
	for _, fn := range updateFunctions {
		fn(db, manifestData)
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

type ManifestData struct {
	Packages []manifest.Package
	Slices   []manifest.Slice
	Paths    []manifest.Path
	Content  []manifest.Content
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
		pathInfo.SHA256 = p.SHA256
		pathInfo.FinalSHA256 = p.FinalSHA256
		pathInfos = append(pathInfos, pathInfo)
	}
	return pathInfos
}

type prefixable interface {
	manifest.Path | manifest.Content | manifest.Package | manifest.Slice
}

func iteratePrefix[T prefixable](db *jsonwall.DB, prefix *T, store *[]T) error {
	iter, err := db.IteratePrefix(prefix)
	if err != nil {
		return err
	}
	for iter.Next() {
		var val T
		err := iter.Get(&val)
		if err != nil {
			return fmt.Errorf("cannot read manifest: %s", err)
		}
		*store = append(*store, val)
	}
	return nil
}

type updFnType func(db *jsonwall.DB, data *ManifestData) error

var updateFunctions = []updFnType{
	func(db *jsonwall.DB, data *ManifestData) error {
		return iteratePrefix(db, &manifest.Package{Kind: "package"}, &data.Packages)
	},
	func(db *jsonwall.DB, data *ManifestData) error {
		return iteratePrefix(db, &manifest.Slice{Kind: "slice"}, &data.Slices)
	},
	func(db *jsonwall.DB, data *ManifestData) error {
		return iteratePrefix(db, &manifest.Path{Kind: "path"}, &data.Paths)
	},
	func(db *jsonwall.DB, data *ManifestData) error {
		return iteratePrefix(db, &manifest.Content{Kind: "content"}, &data.Content)
	},
}
