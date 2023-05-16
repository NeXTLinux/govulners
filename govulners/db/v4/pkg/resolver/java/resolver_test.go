package java

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	govulnersPkg "github.com/nextlinux/govulners/govulners/pkg"
)

func TestResolver_Normalize(t *testing.T) {
	tests := []struct {
		packageName string
		normalized  string
	}{
		{
			packageName: "PyYAML",
			normalized:  "pyyaml",
		},
		{
			packageName: "oslo.concurrency",
			normalized:  "oslo.concurrency",
		},
		{
			packageName: "",
			normalized:  "",
		},
		{
			packageName: "test---1",
			normalized:  "test---1",
		},
		{
			packageName: "AbCd.-__.--.-___.__.--1234____----....XyZZZ",
			normalized:  "abcd.-__.--.-___.__.--1234____----....xyzzz",
		},
	}

	resolver := Resolver{}

	for _, test := range tests {
		resolvedNames := resolver.Normalize(test.packageName)
		assert.Equal(t, resolvedNames, test.normalized)
	}
}

func TestResolver_Resolve(t *testing.T) {
	tests := []struct {
		name     string
		pkg      govulnersPkg.Package
		resolved []string
	}{
		{
			name: "both artifact and manifest 1",
			pkg: govulnersPkg.Package{
				Name:         "ABCD",
				Version:      "1.2.3.4",
				Language:     "java",
				MetadataType: "",
				Metadata: govulnersPkg.JavaMetadata{
					VirtualPath:   "virtual-path-info",
					PomArtifactID: "pom-ARTIFACT-ID-info",
					PomGroupID:    "pom-group-ID-info",
					ManifestName:  "main-section-name-info",
				},
			},
			resolved: []string{"pom-group-id-info:pom-artifact-id-info", "pom-group-id-info:main-section-name-info"},
		},
		{
			name: "both artifact and manifest 2",
			pkg: govulnersPkg.Package{
				ID:   govulnersPkg.ID(uuid.NewString()),
				Name: "a-name",
				Metadata: govulnersPkg.JavaMetadata{
					VirtualPath:   "v-path",
					PomArtifactID: "art-id",
					PomGroupID:    "g-id",
					ManifestName:  "man-name",
				},
			},
			resolved: []string{
				"g-id:art-id",
				"g-id:man-name",
			},
		},
		{
			name: "no group id",
			pkg: govulnersPkg.Package{
				ID:   govulnersPkg.ID(uuid.NewString()),
				Name: "a-name",
				Metadata: govulnersPkg.JavaMetadata{
					VirtualPath:   "v-path",
					PomArtifactID: "art-id",
					ManifestName:  "man-name",
				},
			},
			resolved: []string{},
		},
		{
			name: "only manifest",
			pkg: govulnersPkg.Package{
				ID:   govulnersPkg.ID(uuid.NewString()),
				Name: "a-name",
				Metadata: govulnersPkg.JavaMetadata{
					VirtualPath:  "v-path",
					PomGroupID:   "g-id",
					ManifestName: "man-name",
				},
			},
			resolved: []string{
				"g-id:man-name",
			},
		},
		{
			name: "only artifact",
			pkg: govulnersPkg.Package{
				ID:   govulnersPkg.ID(uuid.NewString()),
				Name: "a-name",
				Metadata: govulnersPkg.JavaMetadata{
					VirtualPath:   "v-path",
					PomArtifactID: "art-id",
					PomGroupID:    "g-id",
				},
			},
			resolved: []string{
				"g-id:art-id",
			},
		},
		{
			name: "no artifact or manifest",
			pkg: govulnersPkg.Package{
				ID:   govulnersPkg.ID(uuid.NewString()),
				Name: "a-name",
				Metadata: govulnersPkg.JavaMetadata{
					VirtualPath: "v-path",
					PomGroupID:  "g-id",
				},
			},
			resolved: []string{},
		},
		{
			name: "with valid purl",
			pkg: govulnersPkg.Package{
				ID:   govulnersPkg.ID(uuid.NewString()),
				Name: "a-name",
				PURL: "pkg:maven/org.nextlinux/b-name@0.2",
			},
			resolved: []string{"org.nextlinux:b-name"},
		},
		{
			name: "ignore invalid pURLs",
			pkg: govulnersPkg.Package{
				ID:   govulnersPkg.ID(uuid.NewString()),
				Name: "a-name",
				PURL: "pkg:BAD/",
				Metadata: govulnersPkg.JavaMetadata{
					VirtualPath:   "v-path",
					PomArtifactID: "art-id",
					PomGroupID:    "g-id",
				},
			},
			resolved: []string{
				"g-id:art-id",
			},
		},
	}

	resolver := Resolver{}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolvedNames := resolver.Resolve(test.pkg)
			assert.ElementsMatch(t, resolvedNames, test.resolved)
		})
	}
}
