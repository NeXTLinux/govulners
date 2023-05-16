package models

import (
	"github.com/nextlinux/govulners/govulners/match"
	"github.com/nextlinux/govulners/govulners/pkg"
	"github.com/nextlinux/govulners/govulners/vulnerability"
	"github.com/anchore/syft/syft/sbom"
)

type PresenterConfig struct {
	Matches          match.Matches
	IgnoredMatches   []match.IgnoredMatch
	Packages         []pkg.Package
	Context          pkg.Context
	MetadataProvider vulnerability.MetadataProvider
	SBOM             *sbom.SBOM
	AppConfig        interface{}
	DBStatus         interface{}
}
