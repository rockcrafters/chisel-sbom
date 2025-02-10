package testutil

import (
	"github.com/rockcrafters/chisel-sbom/internal/builder"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
)

var SampleSinglePackage = []builder.PackageInfo{
	{
		Name:    "test",
		Version: "1.0",
		SHA256:  "sha256",
	},
}

var SampleSingleSlice = []builder.SliceInfo{
	{
		Name: "test_slice",
	},
}

var SampleSinglePathNoFinalSHA256 = []builder.PathInfo{
	{
		Path:   "/test",
		Mode:   "0644",
		Slices: []string{"test_slice"},
		SHA256: "sha256",
	},
}

var SampleSinglePathWithFinalSHA256 = []builder.PathInfo{
	{
		Path:        "/test",
		Mode:        "0644",
		Slices:      []string{"test_slice"},
		SHA256:      "sha256",
		FinalSHA256: "final_sha256",
	},
}

var SampleSinglePathWithEmptyFileSHA256 = []builder.PathInfo{
	{
		Path:        "/test",
		Mode:        "0644",
		Slices:      []string{"test_slice"},
		SHA256:      builder.EmptySHA256,
		FinalSHA256: "final_sha256",
	},
}

var SPDXDocSampleSinglePackage = spdx.Package{
	PackageName:    "test",
	PackageVersion: "1.0",
	FilesAnalyzed:  false,
	PackageChecksums: []spdx.Checksum{
		{
			Algorithm: spdx.SHA256,
			Value:     "sha256",
		},
	},
	PackageDownloadLocation: "NOASSERTION",
	PackageSPDXIdentifier:   spdx.ElementID("Package-test"),
}

var SPDXDocSampleSingleSlice = spdx.Package{
	PackageName:             "test_slice",
	FilesAnalyzed:           false,
	PackageDownloadLocation: "NOASSERTION",
	PackageSPDXIdentifier:   spdx.ElementID("Slice-test_slice"),
}

var SPDXDocSampleSingleFileNoFinalSHA256 = spdx.File{
	FileSPDXIdentifier: spdx.ElementID("File-/test"),
	FileName:           "/test",
	Checksums: []spdx.Checksum{
		{
			Algorithm: spdx.SHA256,
			Value:     "sha256",
		},
	},
	FileCopyrightText: "NOASSERTION",
}

var SPDXDocSampleSingleFileWithFinalSHA256 = spdx.File{
	FileSPDXIdentifier: spdx.ElementID("File-/test"),
	FileName:           "/test",
	Checksums: []spdx.Checksum{
		{
			Algorithm: spdx.SHA256,
			Value:     "final_sha256",
		},
	},
	FileCopyrightText: "NOASSERTION",
}

var SPDXRelSampleSingleDocDescribesPkg = spdx.Relationship{
	RefA:         common.MakeDocElementID("", "DOCUMENT"),
	RefB:         common.MakeDocElementID("", "Package-test"),
	Relationship: "DESCRIBES",
}

var SPDXRelSampleSinglePkgContainsSlice = spdx.Relationship{
	RefA:         common.MakeDocElementID("", "Package-test"),
	RefB:         common.MakeDocElementID("", "Slice-test_slice"),
	Relationship: "CONTAINS",
}

var SPDXRelSampleSingleSliceContainsFile = spdx.Relationship{
	RefA:         common.MakeDocElementID("", "Slice-test_slice"),
	RefB:         common.MakeDocElementID("", "File-/test"),
	Relationship: "CONTAINS",
}

var SPDXRelSampleSingleSliceGeneratesFile = spdx.Relationship{
	RefA:         common.MakeDocElementID("", "Slice-test_slice"),
	RefB:         common.MakeDocElementID("", "File-/test"),
	Relationship: "GENERATES",
}

var SPDXRelSampleSingleFileModifiedBySlice = spdx.Relationship{
	RefA:         common.MakeDocElementID("", "File-/test"),
	RefB:         common.MakeDocElementID("", "Slice-test_slice"),
	Relationship: "FILE_MODIFIED",
}
