package builder

import (
	"fmt"
	"strings"

	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
)

const EmptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

type PackageInfo struct {
	Name    string
	Version string
	SHA256  string
}

type PathInfo struct {
	Path        string
	Mode        string
	Slices      []string
	SHA256      string
	FinalSHA256 string
}

type SliceInfo struct {
	Name string
}

func BuildSPDXDocument(docName string, sliceInfos *[]SliceInfo, packageInfos *[]PackageInfo, pathInfos *[]PathInfo) (*spdx.Document, error) {
	doc := &spdx.Document{
		SPDXVersion:    spdx.Version,
		DataLicense:    spdx.DataLicense,
		SPDXIdentifier: spdx.ElementID("DOCUMENT"),
		DocumentName:   docName,
	}

	// Add packages
	for _, p := range *packageInfos {
		pkg, rln, err := p.buildPackageSection()
		if err != nil {
			return nil, err
		}
		doc.Packages = append(doc.Packages, pkg)
		doc.Relationships = append(doc.Relationships, rln)
	}

	// Add slices
	for _, s := range *sliceInfos {
		pkg, rln, err := s.buildSliceSection()
		if err != nil {
			return nil, err
		}
		doc.Packages = append(doc.Packages, pkg)
		doc.Relationships = append(doc.Relationships, rln)
	}

	// Add paths
	for _, p := range *pathInfos {
		file, rln, err := p.buildPathSection()
		if err != nil {
			return nil, err
		}
		doc.Files = append(doc.Files, file)
		doc.Relationships = append(doc.Relationships, rln...)
	}

	return doc, nil
}

func (p *PackageInfo) SPDXId() string {
	return fmt.Sprintf("Package-%s", p.Name)
}

func (s *SliceInfo) SPDXId() string {
	return fmt.Sprintf("Slice-%s", s.Name)
}

func (p *PathInfo) SPDXId() string {
	return fmt.Sprintf("File-%s", p.Path)
}

func (p *PackageInfo) buildPackageSection() (*spdx.Package, *spdx.Relationship, error) {
	pkg := &spdx.Package{
		PackageName:             p.Name,
		PackageSPDXIdentifier:   common.ElementID(p.SPDXId()),
		PackageVersion:          p.Version,
		PackageChecksums:        []common.Checksum{{Algorithm: common.SHA256, Value: p.SHA256}},
		PackageDownloadLocation: "NOASSERTION",
		FilesAnalyzed:           false,
	}

	rln := &spdx.Relationship{
		RefA:         common.MakeDocElementID("", "DOCUMENT"),
		RefB:         common.MakeDocElementID("", p.SPDXId()),
		Relationship: "DESCRIBES",
	}

	return pkg, rln, nil
}

func (s *SliceInfo) buildSliceSection() (*spdx.Package, *spdx.Relationship, error) {
	pkg := &spdx.Package{
		PackageName:             s.Name,
		PackageSPDXIdentifier:   common.ElementID(s.SPDXId()),
		PackageDownloadLocation: "NOASSERTION",
		FilesAnalyzed:           false,
	}

	packageName := strings.Split(s.Name, "_")[0]
	packageInfo := PackageInfo{
		Name: packageName,
	}
	rln := &spdx.Relationship{
		RefA:         common.MakeDocElementID("", packageInfo.SPDXId()),
		RefB:         common.MakeDocElementID("", s.SPDXId()),
		Relationship: "CONTAINS",
	}

	return pkg, rln, nil
}

func (f *PathInfo) buildPathSection() (*spdx.File, []*spdx.Relationship, error) {
	rln := []*spdx.Relationship{}
	sha256 := f.SHA256
	if f.FinalSHA256 != "" {
		sha256 = f.FinalSHA256
	}
	file := &spdx.File{
		FileName:           f.Path,
		FileSPDXIdentifier: common.ElementID(f.SPDXId()),
		Checksums:          []common.Checksum{{Algorithm: common.SHA256, Value: sha256}},
		FileCopyrightText:  "NOASSERTION",
	}
	for _, s := range f.Slices {
		slice := &SliceInfo{Name: s}
		if f.FinalSHA256 == "" {
			rln = append(rln, &spdx.Relationship{
				RefA:         common.MakeDocElementID("", slice.SPDXId()),
				RefB:         common.MakeDocElementID("", f.SPDXId()),
				Relationship: "CONTAINS",
			})
			continue
		}
		if f.SHA256 == EmptySHA256 {
			rln = append(rln, &spdx.Relationship{
				RefA:         common.MakeDocElementID("", slice.SPDXId()),
				RefB:         common.MakeDocElementID("", f.SPDXId()),
				Relationship: "GENERATES",
			})
		} else {
			rln = append(rln, &spdx.Relationship{
				RefA:         common.MakeDocElementID("", f.SPDXId()),
				RefB:         common.MakeDocElementID("", slice.SPDXId()),
				Relationship: "FILE_MODIFIED",
			})
		}
	}

	return file, rln, nil
}
