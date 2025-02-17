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

var SampleSinglePathModified = []builder.PathInfo{
	{
		Path:        "/test",
		Mode:        "0644",
		Slices:      []string{"test_slice"},
		SHA256:      "sha256",
		FinalSHA256: "final_sha256",
	},
}

var SampleSinglePathGenerated = []builder.PathInfo{
	{
		Path:        "/test",
		Mode:        "0644",
		Slices:      []string{"test_slice"},
		SHA256:      builder.EmptySHA256,
		FinalSHA256: "final_sha256",
	},
}

var SampleSinglePathLnk = []builder.PathInfo{
	{
		Path:   "/test",
		Mode:   "0644",
		Slices: []string{"test_slice"},
		SHA256: "sha256",
		Link:   "/file",
	},
}

var SampleSinglePathHlk = []builder.PathInfo{
	{
		Path:   "/test",
		Mode:   "0644",
		Slices: []string{"test_slice"},
		SHA256: "sha256",
		Inode:  1,
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
	PackageComment:          "This package includes one or more slice(s); see Relationship information.",
}

var SPDXDocSampleSingleSlice = spdx.Package{
	PackageName:             "test_slice",
	FilesAnalyzed:           false,
	PackageDownloadLocation: "NOASSERTION",
	PackageSPDXIdentifier:   spdx.ElementID("Slice-test_slice"),
	PackageComment:          "This slice is a sub-package of the package test; see Relationship information.",
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
	FileComment:       "This file is included in the slice(s) test_slice; see Relationship information.",
}

var SPDXDocSampleSingleFileGenerated = spdx.File{
	FileSPDXIdentifier: spdx.ElementID("File-/test"),
	FileName:           "/test",
	Checksums: []spdx.Checksum{
		{
			Algorithm: spdx.SHA256,
			Value:     "final_sha256",
		},
	},
	FileCopyrightText: "NOASSERTION",
	FileComment:       "This file is inflated by the slice mutation script in the slice test_slice; see Relationship information.",
}

var SPDXDocSampleSingleFileModified = spdx.File{
	FileSPDXIdentifier: spdx.ElementID("File-/test"),
	FileName:           "/test",
	Checksums: []spdx.Checksum{
		{
			Algorithm: spdx.SHA256,
			Value:     "final_sha256",
		},
	},
	FileCopyrightText: "NOASSERTION",
	FileComment:       "This file is mutated by the slice mutation script in the slice test_slice; see Relationship information.",
}

var SPDXDocSampleSingleFileLnk = spdx.File{
	FileSPDXIdentifier: spdx.ElementID("File-/test"),
	FileName:           "/test",
	Checksums: []spdx.Checksum{
		{
			Algorithm: spdx.SHA256,
			Value:     "sha256",
		},
	},
	FileCopyrightText: "NOASSERTION",
	FileComment:       "This file is a symlink to the file /file.",
}

var SPDXDocSampleSingleFileHlk = spdx.File{
	FileSPDXIdentifier: spdx.ElementID("File-/test"),
	FileName:           "/test",
	Checksums: []spdx.Checksum{
		{
			Algorithm: spdx.SHA256,
			Value:     "sha256",
		},
	},
	FileCopyrightText: "NOASSERTION",
	FileComment:       "This file is within the hard link group 1; files in the same hard link group are alias of each other.",
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
	RefA:                common.MakeDocElementID("", "Slice-test_slice"),
	RefB:                common.MakeDocElementID("", "File-/test"),
	Relationship:        "CONTAINS",
	RelationshipComment: "File /test is included in the slice test_slice.",
}

var SPDXRelSampleSingleSliceGeneratesFile = spdx.Relationship{
	RefA:                common.MakeDocElementID("", "Slice-test_slice"),
	RefB:                common.MakeDocElementID("", "File-/test"),
	Relationship:        "GENERATES",
	RelationshipComment: "File /test is inflated by the slice mutation script in the slice test_slice.",
}

var SPDXRelSampleSingleFileModifiedBySlice = spdx.Relationship{
	RefA:                common.MakeDocElementID("", "File-/test"),
	RefB:                common.MakeDocElementID("", "Slice-test_slice"),
	Relationship:        "FILE_MODIFIED",
	RelationshipComment: "File /test is mutated by the slice mutation script in the slice test_slice.",
}
