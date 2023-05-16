package stock

import (
	"strings"

	govulnersPkg "github.com/nextlinux/govulners/govulners/pkg"
)

type Resolver struct {
}

func (r *Resolver) Normalize(name string) string {
	return strings.ToLower(name)
}

func (r *Resolver) Resolve(p govulnersPkg.Package) []string {
	return []string{r.Normalize(p.Name)}
}
