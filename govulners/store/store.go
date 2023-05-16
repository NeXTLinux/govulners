package store

import (
	"github.com/nextlinux/govulners/govulners/match"
	"github.com/nextlinux/govulners/govulners/vulnerability"
)

type Store struct {
	vulnerability.Provider
	vulnerability.MetadataProvider
	match.ExclusionProvider
}
