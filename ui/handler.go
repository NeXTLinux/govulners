package ui

import (
	"context"
	"sync"

	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/jotframe/pkg/frame"

	syftUI "github.com/anchore/syft/ui"
	govulnersEvent "github.com/nextlinux/govulners/govulners/event"
)

type Handler struct {
	syftHandler *syftUI.Handler
}

func NewHandler() *Handler {
	return &Handler{
		syftHandler: syftUI.NewHandler(),
	}
}

func (r *Handler) RespondsTo(event partybus.Event) bool {
	switch event.Type {
	case govulnersEvent.VulnerabilityScanningStarted,
		govulnersEvent.UpdateVulnerabilityDatabase,
		govulnersEvent.DatabaseDiffingStarted:
		return true
	default:
		return r.syftHandler.RespondsTo(event)
	}
}

func (r *Handler) Handle(ctx context.Context, fr *frame.Frame, event partybus.Event, wg *sync.WaitGroup) error {
	switch event.Type {
	case govulnersEvent.VulnerabilityScanningStarted:
		return r.VulnerabilityScanningStartedHandler(ctx, fr, event, wg)
	case govulnersEvent.UpdateVulnerabilityDatabase:
		return r.UpdateVulnerabilityDatabaseHandler(ctx, fr, event, wg)
	case govulnersEvent.DatabaseDiffingStarted:
		return r.DatabaseDiffingStartedHandler(ctx, fr, event, wg)
	default:
		return r.syftHandler.Handle(ctx, fr, event, wg)
	}
}
