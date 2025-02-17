package converter_test

import (
	"io"
	"strings"

	"github.com/canonical/chisel/public/manifest"
	"github.com/rockcrafters/chisel-sbom/internal/builder"
	"github.com/rockcrafters/chisel-sbom/internal/converter"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
	. "gopkg.in/check.v1"
)

type ProcessTest struct {
	summary      string
	manifestData converter.ManifestData
	packageInfos []builder.PackageInfo
	pathInfos    []builder.PathInfo
	sliceInfos   []builder.SliceInfo
	error        string
}

var processTests = []ProcessTest{
	{
		summary: "Converts packages",
		manifestData: converter.ManifestData{
			Packages: []manifest.Package{
				{
					Kind:    "package",
					Name:    "test",
					Version: "1.0",
					Digest:  "sha256",
					Arch:    "amd64",
				},
			},
		},
		packageInfos: []builder.PackageInfo{
			{
				Name:    "test",
				Version: "1.0",
				SHA256:  "sha256",
			},
		},
	}, {
		summary: "Converts paths",
		manifestData: converter.ManifestData{
			Paths: []manifest.Path{
				{
					Kind:        "path",
					Path:        "/test",
					Mode:        "0644",
					Slices:      []string{"test"},
					SHA256:      "sha256",
					FinalSHA256: "final_sha256",
					Size:        1024,
					Link:        "/file",
					Inode:       1,
				},
			},
		},
		pathInfos: []builder.PathInfo{
			{
				Path:        "/test",
				Mode:        "0644",
				Slices:      []string{"test"},
				SHA256:      "sha256",
				FinalSHA256: "final_sha256",
				Link:        "/file",
				Inode:       1,
			},
		},
	}, {
		summary: "Converts slices",
		manifestData: converter.ManifestData{
			Slices: []manifest.Slice{
				{
					Kind: "slice",
					Name: "test",
				},
			},
		},
		sliceInfos: []builder.SliceInfo{
			{
				Name: "test",
			},
		},
	},
}

type ConverterTest struct {
	summary      string
	jsonwall     string
	spdxDocument spdx.Document
	error        string
}

var converterTests = []ConverterTest{
	{
		summary: "Converts manifest data to SPDX document",
		jsonwall: `
			{"jsonwall":"1.0","schema":"1.0","count":3}
			{"kind":"package","name":"test","version":"1.0","sha256":"sha256","arch":"amd64"}
			{"kind":"path","path":"/test","mode":"0644","slices":["test_slice"],"sha256":"sha256","size":1024}
			{"kind":"slice","name":"test_slice"}
		`,
		spdxDocument: spdx.Document{
			SPDXVersion:    spdx.Version,
			DataLicense:    spdx.DataLicense,
			SPDXIdentifier: spdx.ElementID("DOCUMENT"),
			DocumentName:   "test",
			Packages: []*spdx.Package{
				{
					PackageName:             "test",
					PackageVersion:          "1.0",
					PackageSPDXIdentifier:   spdx.ElementID("Package-test"),
					FilesAnalyzed:           false,
					PackageDownloadLocation: "NOASSERTION",
					PackageChecksums:        []spdx.Checksum{{Algorithm: spdx.SHA256, Value: "sha256"}},
					PackageComment:          "This package includes one or more slice(s); see Relationship information.",
				}, {
					PackageName:             "test_slice",
					PackageSPDXIdentifier:   spdx.ElementID("Slice-test_slice"),
					FilesAnalyzed:           false,
					PackageDownloadLocation: "NOASSERTION",
					PackageComment:          "This slice is a sub-package of the package test; see Relationship information.",
				},
			},
			Files: []*spdx.File{
				{
					FileName:           "/test",
					FileSPDXIdentifier: spdx.ElementID("File-/test"),
					Checksums:          []spdx.Checksum{{Algorithm: spdx.SHA256, Value: "sha256"}},
					FileCopyrightText:  "NOASSERTION",
					FileComment:        "This file is included in the slice(s) test_slice; see Relationship information.",
				},
			},
			Relationships: []*spdx.Relationship{
				{
					RefA:         common.MakeDocElementID("", "DOCUMENT"),
					RefB:         common.MakeDocElementID("", "Package-test"),
					Relationship: "DESCRIBES",
				}, {
					RefA:         common.MakeDocElementID("", "Package-test"),
					RefB:         common.MakeDocElementID("", "Slice-test_slice"),
					Relationship: "CONTAINS",
				}, {
					RefA:                common.MakeDocElementID("", "Slice-test_slice"),
					RefB:                common.MakeDocElementID("", "File-/test"),
					Relationship:        "CONTAINS",
					RelationshipComment: "File /test is included in the slice test_slice.",
				},
			},
		},
	}, {
		summary: "Path with non-empty SHA256 and FinalSHA256 has relationship FILE_MODIFIED",
		jsonwall: `
			{"jsonwall":"1.0","schema":"1.0","count":3}
			{"kind":"package","name":"test","version":"1.0","sha256":"sha256"}
			{"kind":"path","path":"/test","mode":"0644","slices":["test_slice"],"sha256":"sha256","final_sha256":"final_sha256","size":1024}
			{"kind":"slice","name":"test_slice"}
		`,
		spdxDocument: spdx.Document{
			SPDXVersion:    spdx.Version,
			DataLicense:    spdx.DataLicense,
			SPDXIdentifier: spdx.ElementID("DOCUMENT"),
			DocumentName:   "test",
			Packages: []*spdx.Package{
				{
					PackageName:             "test",
					PackageVersion:          "1.0",
					PackageSPDXIdentifier:   spdx.ElementID("Package-test"),
					FilesAnalyzed:           false,
					PackageDownloadLocation: "NOASSERTION",
					PackageChecksums:        []spdx.Checksum{{Algorithm: spdx.SHA256, Value: "sha256"}},
					PackageComment:          "This package includes one or more slice(s); see Relationship information.",
				}, {
					PackageName:             "test_slice",
					PackageSPDXIdentifier:   spdx.ElementID("Slice-test_slice"),
					FilesAnalyzed:           false,
					PackageDownloadLocation: "NOASSERTION",
					PackageComment:          "This slice is a sub-package of the package test; see Relationship information.",
				},
			},
			Files: []*spdx.File{
				{
					FileName:           "/test",
					FileSPDXIdentifier: spdx.ElementID("File-/test"),
					Checksums:          []spdx.Checksum{{Algorithm: spdx.SHA256, Value: "final_sha256"}},
					FileCopyrightText:  "NOASSERTION",
					FileComment:        "This file is mutated by the slice mutation script in the slice test_slice; see Relationship information.",
				},
			},
			Relationships: []*spdx.Relationship{
				{
					RefA:         common.MakeDocElementID("", "DOCUMENT"),
					RefB:         common.MakeDocElementID("", "Package-test"),
					Relationship: "DESCRIBES",
				}, {
					RefA:         common.MakeDocElementID("", "Package-test"),
					RefB:         common.MakeDocElementID("", "Slice-test_slice"),
					Relationship: "CONTAINS",
				}, {
					RefA:                common.MakeDocElementID("", "File-/test"),
					RefB:                common.MakeDocElementID("", "Slice-test_slice"),
					Relationship:        "FILE_MODIFIED",
					RelationshipComment: "File /test is mutated by the slice mutation script in the slice test_slice.",
				},
			},
		},
	},
}

func (s *S) TestProcessManifestData(c *C) {
	for _, test := range processTests {
		c.Logf("Running test: %s", test.summary)
		packageInfos := test.manifestData.ProcessPackages()
		c.Assert(packageInfos, DeepEquals, test.packageInfos)
		pathInfos := test.manifestData.ProcessPaths()
		c.Assert(pathInfos, DeepEquals, test.pathInfos)
		sliceInfos := test.manifestData.ProcessSlices()
		c.Assert(sliceInfos, DeepEquals, test.sliceInfos)
	}
}

func (s *S) TestConvert(c *C) {
	for _, test := range converterTests {
		c.Logf("Running test: %s", test.summary)
		lines := strings.Split(strings.TrimSpace(test.jsonwall), "\n")
		trimmedLines := make([]string, 0, len(lines))
		for _, line := range lines {
			trimmedLines = append(trimmedLines, strings.TrimLeft(line, "\t"))
		}
		test.jsonwall = strings.Join(trimmedLines, "\n")
		var reader io.Reader = strings.NewReader(test.jsonwall)
		doc, err := converter.Convert(reader)
		c.Assert(err, IsNil)
		c.Assert(doc, DeepEquals, &test.spdxDocument)
	}
}
