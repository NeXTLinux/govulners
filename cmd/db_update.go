package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/wagoodman/go-partybus"

	"github.com/nextlinux/govulners/govulners/db"
	"github.com/nextlinux/govulners/govulners/event"
	"github.com/nextlinux/govulners/internal/bus"
	"github.com/nextlinux/govulners/internal/log"
	"github.com/nextlinux/govulners/internal/ui"
	"github.com/nextlinux/stereoscope"
)

var dbUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "download the latest vulnerability database",
	Args:  cobra.ExactArgs(0),
	RunE:  runDBUpdateCmd,
}

func init() {
	dbCmd.AddCommand(dbUpdateCmd)
}

func startDBUpdateCmd() <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)
		dbCurator, err := db.NewCurator(appConfig.DB.ToCuratorConfig())
		if err != nil {
			errs <- err
			return
		}
		updated, err := dbCurator.Update()
		if err != nil {
			errs <- fmt.Errorf("unable to update vulnerability database: %+v", err)
		}

		result := "No vulnerability database update available\n"
		if updated {
			result = "Vulnerability database updated to latest version!\n"
		}

		bus.Publish(partybus.Event{
			Type:  event.NonRootCommandFinished,
			Value: result,
		})
	}()
	return errs
}

func runDBUpdateCmd(_ *cobra.Command, _ []string) error {
	reporter, closer, err := reportWriter()
	defer func() {
		if err := closer(); err != nil {
			log.Warnf("unable to write to report destination: %+v", err)
		}
	}()
	if err != nil {
		return err
	}
	return eventLoop(
		startDBUpdateCmd(),
		setupSignals(),
		eventSubscription,
		stereoscope.Cleanup,
		ui.Select(isVerbose(), appConfig.Quiet, reporter)...,
	)
}
