package portage

import (
	"fmt"

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
	return []syftPkg.Type{syftPkg.PortagePkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.PortageMatcher
}

func (m *Matcher) Match(store vulnerability.Provider, d *distro.Distro, p pkg.Package) ([]match.Match, error) {
	matches, err := search.ByPackageDistro(store, d, p, m.Type())
	if err != nil {
		return nil, fmt.Errorf("failed to find vulnerabilities: %w", err)
	}

	return matches, nil
}
