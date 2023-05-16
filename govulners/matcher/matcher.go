package matcher

import (
	"github.com/nextlinux/govulners/govulners/distro"
	"github.com/nextlinux/govulners/govulners/match"
	"github.com/nextlinux/govulners/govulners/pkg"
	"github.com/nextlinux/govulners/govulners/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type Matcher interface {
	PackageTypes() []syftPkg.Type
	Type() match.MatcherType
	Match(vulnerability.Provider, *distro.Distro, pkg.Package) ([]match.Match, error)
}
