package resolver

import (
	govulnersPkg "github.com/nextlinux/govulners/govulners/pkg"
)

type Resolver interface {
	Normalize(string) string
	Resolve(p govulnersPkg.Package) []string
}
