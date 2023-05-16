package qualifier

import "github.com/nextlinux/govulners/govulners/pkg"

type Qualifier interface {
	Satisfied(p pkg.Package) (bool, error)
}
