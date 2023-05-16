package qualifier

import (
	"fmt"

	"github.com/nextlinux/govulners/govulners/pkg/qualifier"
)

type Qualifier interface {
	fmt.Stringer
	Parse() qualifier.Qualifier
}
