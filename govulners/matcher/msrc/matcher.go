package msrc

import (
	"github.com/nextlinux/govulners/govulners/distro"
	"github.com/nextlinux/govulners/govulners/match"
	"github.com/nextlinux/govulners/govulners/pkg"
	"github.com/nextlinux/govulners/govulners/search"
	"github.com/nextlinux/govulners/govulners/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type Matcher struct {
}

func (m *Matcher) PackageTypes() []syftPkg.Type {
	// This looks like there is a special package, but in reality, this is just
	// a workaround. MSRC matching is done at the KB-patch level, and so this
	// treats KBs as "packages" but they aren't packages, they are patches
	return []syftPkg.Type{syftPkg.KbPkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.MsrcMatcher
}

func (m *Matcher) Match(store vulnerability.Provider, d *distro.Distro, p pkg.Package) ([]match.Match, error) {
	// find KB matches for the MSFT version given in the package and version.
	// The "distro" holds the information about the Windows version, and its
	// patch (KB)
	return search.ByCriteria(store, d, p, m.Type(), search.ByDistro)
}
