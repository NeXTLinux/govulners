//go:build linux || darwin
// +build linux darwin

package ui

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/gookit/color"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/jotframe/pkg/frame"

	govulnersEventParsers "github.com/nextlinux/govulners/govulners/event/parsers"
	"github.com/nextlinux/govulners/internal"
	"github.com/nextlinux/govulners/internal/version"
)

func handleAppUpdateAvailable(_ context.Context, fr *frame.Frame, event partybus.Event, _ *sync.WaitGroup) error {
	newVersion, err := govulnersEventParsers.ParseAppUpdateAvailable(event)
	if err != nil {
		return fmt.Errorf("bad %s event: %w", event.Type, err)
	}

	line, err := fr.Prepend()
	if err != nil {
		return err
	}

	message := color.Magenta.Sprintf("New version of %s is available: %s (currently running: %s)", internal.ApplicationName, newVersion, version.FromBuild().Version)
	_, _ = io.WriteString(line, message)

	return nil
}
