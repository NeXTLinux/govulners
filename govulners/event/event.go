package event

import "github.com/wagoodman/go-partybus"

const (
	AppUpdateAvailable            partybus.EventType = "govulners-app-update-available"
	UpdateVulnerabilityDatabase   partybus.EventType = "govulners-update-vulnerability-database"
	VulnerabilityScanningStarted  partybus.EventType = "govulners-vulnerability-scanning-started"
	VulnerabilityScanningFinished partybus.EventType = "govulners-vulnerability-scanning-finished"
	NonRootCommandFinished        partybus.EventType = "govulners-non-root-command-finished"
	DatabaseDiffingStarted        partybus.EventType = "govulners-database-diffing-started"
)
