package internal

import (
	"errors"
	"fmt"

	"github.com/ebfe/scard"
	"github.com/ethereum/go-ethereum/log"
)

// ConnectToCard establishes a connection to a smart card reader.
// If readerName is non-empty, it uses that specific reader; otherwise auto-detects.
// Returns a cleanup function that must be deferred.
func ConnectToCard(readerName string) (*scard.Card, func(), error) {
	ctx, err := scard.EstablishContext()
	if err != nil {
		return nil, nil, fmt.Errorf("error establishing card context: %w", err)
	}

	readers, err := ctx.ListReaders()
	if err != nil {
		ctx.Release()
		return nil, nil, fmt.Errorf("error getting readers: %w", err)
	}

	if len(readers) == 0 {
		ctx.Release()
		return nil, nil, errors.New("no smartcard reader found")
	}

	var reader string
	if readerName != "" {
		found := false
		for _, r := range readers {
			if r == readerName {
				reader = r
				found = true
				break
			}
		}
		if !found {
			ctx.Release()
			return nil, nil, fmt.Errorf("reader not found: %s (available: %v)", readerName, readers)
		}
	} else {
		// Auto-detect: wait for first card present
		index, err := waitForCard(ctx, readers)
		if err != nil {
			ctx.Release()
			return nil, nil, fmt.Errorf("error waiting for card: %w", err)
		}
		reader = readers[index]
	}

	log.Info("connecting to card", "reader", reader)
	card, err := ctx.Connect(reader, scard.ShareShared, scard.ProtocolAny)
	if err != nil {
		ctx.Release()
		return nil, nil, fmt.Errorf("error connecting to card: %w", err)
	}

	status, err := card.Status()
	if err != nil {
		card.Disconnect(scard.ResetCard)
		ctx.Release()
		return nil, nil, fmt.Errorf("error getting card status: %w", err)
	}

	switch status.ActiveProtocol {
	case scard.ProtocolT0:
		log.Debug("card protocol", "T", "0")
	case scard.ProtocolT1:
		log.Debug("card protocol", "T", "1")
	default:
		log.Debug("card protocol", "T", "unknown")
	}

	cleanup := func() {
		if err := card.Disconnect(scard.ResetCard); err != nil {
			log.Error("error disconnecting card", "error", err)
		}
		if err := ctx.Release(); err != nil {
			log.Error("error releasing context", "error", err)
		}
	}

	return card, cleanup, nil
}

func waitForCard(ctx *scard.Context, readers []string) (int, error) {
	rs := make([]scard.ReaderState, len(readers))

	for i := range rs {
		rs[i].Reader = readers[i]
		rs[i].CurrentState = scard.StateUnaware
	}

	for {
		for i := range rs {
			if rs[i].EventState&scard.StatePresent != 0 {
				return i, nil
			}
			rs[i].CurrentState = rs[i].EventState
		}

		err := ctx.GetStatusChange(rs, -1)
		if err != nil {
			return -1, err
		}
	}
}
