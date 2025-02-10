package builder_test

import (
	"github.com/rockcrafters/chisel-sbom/internal/builder"
	"github.com/rockcrafters/chisel-sbom/internal/testutil"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
	. "gopkg.in/check.v1"
)

type BuilderTest struct {
	summary      string
	packageInfos []builder.PackageInfo
	pathInfos    []builder.PathInfo
	sliceInfos   []builder.SliceInfo
	spdxDocument spdx.Document
	error        string
}

var builerTests = []BuilderTest{
	{
		summary:      "Builds package section",
		packageInfos: testutil.SampleSinglePackage,
		spdxDocument: spdx.Document{
			SPDXVersion:    spdx.Version,
			DataLicense:    spdx.DataLicense,
			SPDXIdentifier: spdx.ElementID("DOCUMENT"),
			DocumentName:   "test",
			Packages: []*spdx.Package{
				{
					PackageName:    "test",
					PackageVersion: "1.0",
					PackageChecksums: []spdx.Checksum{
						{
							Algorithm: spdx.SHA256,
							Value:     "sha256",
						},
					},
					PackageDownloadLocation: "NOASSERTION",
					PackageSPDXIdentifier:   spdx.ElementID("Package-test"),
				},
			},
			Relationships: []*spdx.Relationship{
				{
					RefA:         common.MakeDocElementID("", "DOCUMENT"),
					RefB:         common.MakeDocElementID("", "Package-test"),
					Relationship: "DESCRIBES",
				},
			},
		},
	}, {
		summary:      "Builds slice section",
		packageInfos: testutil.SampleSinglePackage,
		sliceInfos:   testutil.SampleSingleSlice,
		spdxDocument: spdx.Document{
			SPDXVersion:    spdx.Version,
			DataLicense:    spdx.DataLicense,
			SPDXIdentifier: spdx.ElementID("DOCUMENT"),
			DocumentName:   "test",
			Packages: []*spdx.Package{
				&testutil.SPDXDocSampleSinglePackage,
				&testutil.SPDXDocSampleSingleSlice,
			},
			Relationships: []*spdx.Relationship{
				&testutil.SPDXRelSampleSingleDocDescribesPkg,
				&testutil.SPDXRelSampleSinglePkgContainsSlice,
			},
		},
	}, {
		summary:      "Builds file section",
		packageInfos: testutil.SampleSinglePackage,
		sliceInfos:   testutil.SampleSingleSlice,
		pathInfos:    testutil.SampleSinglePathNoFinalSHA256,
		spdxDocument: spdx.Document{
			SPDXVersion:    spdx.Version,
			DataLicense:    spdx.DataLicense,
			SPDXIdentifier: spdx.ElementID("DOCUMENT"),
			DocumentName:   "test",
			Packages: []*spdx.Package{
				&testutil.SPDXDocSampleSinglePackage,
				&testutil.SPDXDocSampleSingleSlice,
			},
			Files: []*spdx.File{
				&testutil.SPDXDocSampleSingleFileNoFinalSHA256,
			},
			Relationships: []*spdx.Relationship{
				&testutil.SPDXRelSampleSingleDocDescribesPkg,
				&testutil.SPDXRelSampleSinglePkgContainsSlice,
				&testutil.SPDXRelSampleSingleSliceContainsFile,
			},
		},
	}, {
		summary:      "Builds file section with final SHA256",
		packageInfos: testutil.SampleSinglePackage,
		sliceInfos:   testutil.SampleSingleSlice,
		pathInfos:    testutil.SampleSinglePathWithFinalSHA256,
		spdxDocument: spdx.Document{
			SPDXVersion:    spdx.Version,
			DataLicense:    spdx.DataLicense,
			SPDXIdentifier: spdx.ElementID("DOCUMENT"),
			DocumentName:   "test",
			Packages: []*spdx.Package{
				&testutil.SPDXDocSampleSinglePackage,
				&testutil.SPDXDocSampleSingleSlice,
			},
			Files: []*spdx.File{
				&testutil.SPDXDocSampleSingleFileWithFinalSHA256,
			},
			Relationships: []*spdx.Relationship{
				&testutil.SPDXRelSampleSingleDocDescribesPkg,
				&testutil.SPDXRelSampleSinglePkgContainsSlice,
				&testutil.SPDXRelSampleSingleFileModifiedBySlice,
			},
		},
	}, {
		summary:      "Builds file section with final SHA256 and empty file inital SHA256",
		packageInfos: testutil.SampleSinglePackage,
		sliceInfos:   testutil.SampleSingleSlice,
		pathInfos:    testutil.SampleSinglePathWithEmptyFileSHA256,
		spdxDocument: spdx.Document{
			SPDXVersion:    spdx.Version,
			DataLicense:    spdx.DataLicense,
			SPDXIdentifier: spdx.ElementID("DOCUMENT"),
			DocumentName:   "test",
			Packages: []*spdx.Package{
				&testutil.SPDXDocSampleSinglePackage,
				&testutil.SPDXDocSampleSingleSlice,
			},
			Files: []*spdx.File{
				&testutil.SPDXDocSampleSingleFileWithFinalSHA256,
			},
			Relationships: []*spdx.Relationship{
				&testutil.SPDXRelSampleSingleDocDescribesPkg,
				&testutil.SPDXRelSampleSinglePkgContainsSlice,
				&testutil.SPDXRelSampleSingleSliceGeneratesFile,
			},
		},
	}, {
		summary:      "Builds doc for one slice with two files",
		packageInfos: testutil.SampleSinglePackage,
		sliceInfos:   testutil.SampleSingleSlice,
		pathInfos: append(testutil.SampleSinglePathWithEmptyFileSHA256,
			builder.PathInfo{
				Path:   "/test2",
				Mode:   "0644",
				SHA256: "sha256",
				Slices: []string{"test_slice"},
			}),
		spdxDocument: spdx.Document{
			SPDXVersion:    spdx.Version,
			DataLicense:    spdx.DataLicense,
			SPDXIdentifier: spdx.ElementID("DOCUMENT"),
			DocumentName:   "test",
			Packages: []*spdx.Package{
				&testutil.SPDXDocSampleSinglePackage,
				&testutil.SPDXDocSampleSingleSlice,
			},
			Files: []*spdx.File{
				&testutil.SPDXDocSampleSingleFileWithFinalSHA256,
				{
					FileName:           "/test2",
					FileSPDXIdentifier: spdx.ElementID("File-/test2"),
					Checksums: []spdx.Checksum{
						{
							Algorithm: spdx.SHA256,
							Value:     "sha256",
						},
					},
					FileCopyrightText: "NOASSERTION",
				},
			},
			Relationships: []*spdx.Relationship{
				&testutil.SPDXRelSampleSingleDocDescribesPkg,
				&testutil.SPDXRelSampleSinglePkgContainsSlice,
				&testutil.SPDXRelSampleSingleSliceGeneratesFile,
				{
					RefA:         common.MakeDocElementID("", "Slice-test_slice"),
					RefB:         common.MakeDocElementID("", "File-/test2"),
					Relationship: "CONTAINS",
				},
			},
		},
	}, {
		summary:      "Builds doc for two slices having a shared file",
		packageInfos: testutil.SampleSinglePackage,
		sliceInfos: append(testutil.SampleSingleSlice,
			builder.SliceInfo{
				Name: "test_slice2",
			},
		),
		pathInfos: []builder.PathInfo{
			{
				Path:   "/test",
				Mode:   "0644",
				SHA256: "sha256",
				Slices: []string{"test_slice", "test_slice2"},
			},
		},
		spdxDocument: spdx.Document{
			SPDXVersion:    spdx.Version,
			DataLicense:    spdx.DataLicense,
			SPDXIdentifier: spdx.ElementID("DOCUMENT"),
			DocumentName:   "test",
			Packages: []*spdx.Package{
				&testutil.SPDXDocSampleSinglePackage,
				&testutil.SPDXDocSampleSingleSlice,
				{
					PackageName:             "test_slice2",
					PackageSPDXIdentifier:   spdx.ElementID("Slice-test_slice2"),
					FilesAnalyzed:           false,
					PackageDownloadLocation: "NOASSERTION",
				},
			},
			Files: []*spdx.File{
				&testutil.SPDXDocSampleSingleFileNoFinalSHA256,
			},
			Relationships: []*spdx.Relationship{
				&testutil.SPDXRelSampleSingleDocDescribesPkg,
				&testutil.SPDXRelSampleSinglePkgContainsSlice,
				{
					RefA:         common.MakeDocElementID("", "Package-test"),
					RefB:         common.MakeDocElementID("", "Slice-test_slice2"),
					Relationship: "CONTAINS",
				},
				&testutil.SPDXRelSampleSingleSliceContainsFile,
				{
					RefA:         common.MakeDocElementID("", "Slice-test_slice2"),
					RefB:         common.MakeDocElementID("", "File-/test"),
					Relationship: "CONTAINS",
				},
			},
		},
	},
}

func (s *S) TestBuilder(c *C) {
	for _, test := range builerTests {
		c.Logf("Running test: %s", test.summary)
		doc, err := builder.BuildSPDXDocument("test", &test.sliceInfos, &test.packageInfos, &test.pathInfos)
		c.Assert(err, IsNil)
		c.Assert(doc, DeepEquals, &test.spdxDocument)
	}
}
