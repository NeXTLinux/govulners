package govulners

import (
	"github.com/wagoodman/go-partybus"

	"github.com/nextlinux/gologger"
	"github.com/nextlinux/govulners/internal/bus"
	"github.com/nextlinux/govulners/internal/log"
)

func SetLogger(logger logger.Logger) {
	log.Log = logger
}

func SetBus(b *partybus.Bus) {
	bus.SetPublisher(b)
}
