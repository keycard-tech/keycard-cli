package cmd

import (
	"fmt"
	"os"

	keycard "github.com/keycard-tech/keycard-go/v4"
	"github.com/keycard-tech/keycard-go/v4/globalplatform"
	keycardio "github.com/keycard-tech/keycard-go/v4/io"
	"github.com/keycard-tech/keycard-go/v4/types"
	"github.com/urfave/cli/v3"

	"github.com/keycard-tech/keycard-cli/internal"
)

// AuthLevel controls how far the authentication pipeline proceeds.
type AuthLevel int

const (
	// AuthNone — connect, create CommandSet, Select. No secure channel.
	AuthNone AuthLevel = iota
	// AuthSecureChannel — open secure channel (pair on V1 if pairing password available). No PIN check.
	AuthSecureChannel
	// AuthPIN — full auth: secure channel + PIN verification.
	AuthPIN
)

// runCard connects to the card, creates a keycard.CommandSet, selects the
// applet, runs the auth pipeline up to the requested level, then executes fn.
func runCard(cmd *cli.Command, level AuthLevel, fn func(kc *keycard.CommandSet, cmd *cli.Command) error) (retErr error) {
	card, cleanup, err := internal.ConnectToCard(cmd.String("reader"))
	if err != nil {
		return err
	}
	defer cleanup()

	ch := keycardio.NewNormalChannel(card)
	kc, err := newCommandSet(ch, cmd)
	if err != nil {
		return err
	}

	if err := kc.Select(); err != nil {
		return err
	}

	secrets := internal.ResolveSecrets(
		cmd.String("pin"),
		cmd.String("puk"),
		cmd.String("pairing-password"),
	)

	// paired tracks whether we paired on V1 so the deferred unpair
	// only runs when we actually established a pairing.
	paired := false

	switch level {
	case AuthNone:
		// No auth needed
	case AuthSecureChannel:
		// Open secure channel (pair on V1 if pairing password available)
		if !internal.IsSecureChannelV2(kc) && secrets.PairingPass != "" {
			if err := kc.AutoPairWithSecret(keycard.PairingPasswordToSecret(secrets.PairingPass)); err != nil {
				return err
			}
			paired = true
			// Defer unpair immediately after pairing — if any later step
			// fails, we still clean up the pairing slot.
			defer func() {
				if paired && !internal.IsSecureChannelV2(kc) {
					if err := internal.AutoUnpair(kc); err != nil && retErr == nil {
						retErr = fmt.Errorf("error unpairing from card: %w", err)
					}
				}
			}()
		}
		if err := kc.AutoOpenSecureChannel(); err != nil {
			return err
		}
		// On V1, the UNPAIR command requires a verified PIN. For
			// AuthSecureChannel-level commands we normally don't verify the
			// PIN, but if one is available we verify it so that the deferred
			// unpair actually succeeds. Without this, every invocation of a
			// read-only command (get-status, get-data, etc.) permanently
			// consumes one of the card's 5 pairing slots.
			if !internal.IsSecureChannelV2(kc) && secrets.Pin != "" {
				if err := kc.VerifyPIN(secrets.Pin); err != nil {
					return err
				}
			}
	case AuthPIN:
		// Full auth: secure channel + PIN verification
			if !internal.IsSecureChannelV2(kc) && secrets.PairingPass != "" {
				if err := kc.AutoPairWithSecret(keycard.PairingPasswordToSecret(secrets.PairingPass)); err != nil {
					return err
				}
				paired = true
				// Defer unpair immediately after pairing.
				defer func() {
					if paired && !internal.IsSecureChannelV2(kc) {
						if err := internal.AutoUnpair(kc); err != nil && retErr == nil {
							retErr = fmt.Errorf("error unpairing from card: %w", err)
						}
					}
				}()
			}
			if err := kc.AutoOpenSecureChannel(); err != nil {
				return err
			}

			if err := internal.RequirePIN(secrets); err != nil {
				return err
			}
			if err := kc.VerifyPIN(secrets.Pin); err != nil {
				return err
			}
	}

	return fn(kc, cmd)
}

// runGP connects to the card, creates a GlobalPlatform CommandSet, opens a GP
// secure channel, then executes fn.
func runGP(cmd *cli.Command, fn func(gp *globalplatform.CommandSet, cmd *cli.Command) error) error {
	card, cleanup, err := internal.ConnectToCard(cmd.String("reader"))
	if err != nil {
		return err
	}
	defer cleanup()

	ch := keycardio.NewNormalChannel(card)
	gp := globalplatform.NewCommandSet(ch)

	if err := gp.OpenSecureChannel(); err != nil {
		return err
	}

	return fn(gp, cmd)
}

// runCash connects to the card, creates a Cash CommandSet, selects the Cash
// applet, then executes fn. No secure channel or PIN required.
func runCash(cmd *cli.Command, fn func(cashKC *keycard.CashCommandSet, cmd *cli.Command) error) error {
	card, cleanup, err := internal.ConnectToCard(cmd.String("reader"))
	if err != nil {
		return err
	}
	defer cleanup()

	ch := keycardio.NewNormalChannel(card)
	cashKC := keycard.NewCashCommandSet(ch)

	if err := cashKC.Select(); err != nil {
		return err
	}

	return fn(cashKC, cmd)
}

// runIdent connects to the card, creates an Ident CommandSet, then executes
// fn. No secure channel or PIN required.
func runIdent(cmd *cli.Command, fn func(identKC *keycard.IdentCommandSet, cmd *cli.Command) error) error {
	card, cleanup, err := internal.ConnectToCard(cmd.String("reader"))
	if err != nil {
		return err
	}
	defer cleanup()

	ch := keycardio.NewNormalChannel(card)
	identKC := keycard.NewIdentCommandSet(ch)

	return fn(identKC, cmd)
}

// testCardCA is the CA public key for test cards (hex, 33 bytes compressed).
const testCardCA = "025877220AAAE6E54A6F974602D5995C0FE24A3EA7DDABD8644BEC795B9DA00743"

// newCommandSet creates a keycard.CommandSet, optionally using a custom CA
// public key and/or whitelisted card identity key from CLI flags.
// Priority: CLI flags > environment variables.
func newCommandSet(ch types.Channel, cmd *cli.Command) (*keycard.CommandSet, error) {
	cardCA := cmd.String("card-ca")
	whitelistCard := cmd.String("whitelist-card")

	// --test-card is a shortcut for --card-ca with the test CA public key
	if cmd.Bool("test-card") && cardCA == "" {
		cardCA = testCardCA
	}

	// Fallback to environment variables
	if cardCA == "" {
		if v := os.Getenv("KEYCARD_CARD_CA"); v != "" {
			cardCA = v
		}
	}
	if whitelistCard == "" {
		if v := os.Getenv("KEYCARD_WHITELIST_CARD"); v != "" {
			whitelistCard = v
		}
	}
	// KEYCARD_TEST_CARD env var acts like --test-card flag
	if cardCA == "" {
		if v := os.Getenv("KEYCARD_TEST_CARD"); v != "" && v != "0" && v != "false" {
			cardCA = testCardCA
		}
	}

	if cardCA == "" && whitelistCard == "" {
		return keycard.NewCommandSet(ch), nil
	}

	var caPublicKeys [][33]byte
	var whitelistedCardKeys [][33]byte

	if cardCA != "" {
		caBytes, err := internal.ParseHex(cardCA)
		if err != nil {
			return nil, fmt.Errorf("invalid card-ca hex: %w", err)
		} else if len(caBytes) != 33 {
			return nil, fmt.Errorf("card-ca must be 33 bytes (compressed public key), got %d", len(caBytes))
		} else {
			var caKey [33]byte
			copy(caKey[:], caBytes)
			caPublicKeys = append(caPublicKeys, caKey)
		}
	}

	if whitelistCard != "" {
		wlBytes, err := internal.ParseHex(whitelistCard)
		if err != nil {
			return nil, fmt.Errorf("invalid whitelist-card hex: %w", err)
		} else if len(wlBytes) != 33 {
			return nil, fmt.Errorf("whitelist-card must be 33 bytes (compressed public key), got %d", len(wlBytes))
		} else {
			var wlKey [33]byte
			copy(wlKey[:], wlBytes)
			whitelistedCardKeys = append(whitelistedCardKeys, wlKey)
		}
	}

	return keycard.NewCommandSetWithCAs(ch, caPublicKeys, whitelistedCardKeys), nil
}
