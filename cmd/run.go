package cmd

import (
	"fmt"
	"os"

	keycard "github.com/status-im/keycard-go"
	"github.com/status-im/keycard-go/globalplatform"
	keycardio "github.com/status-im/keycard-go/io"
	"github.com/status-im/keycard-go/types"
	"github.com/urfave/cli/v3"

	"github.com/status-im/keycard-cli/internal"
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
func runCard(cmd *cli.Command, level AuthLevel, fn func(kc *keycard.CommandSet, cmd *cli.Command) error) error {
	card, cleanup, err := internal.ConnectToCard(cmd.String("reader"))
	if err != nil {
		return err
	}
	defer cleanup()

	ch := keycardio.NewNormalChannel(card)
	kc := newCommandSet(ch, cmd)

	if err := kc.Select(); err != nil {
		return err
	}

	secrets := internal.ResolveSecrets(
		cmd.String("pin"),
		cmd.String("puk"),
		cmd.String("pairing-password"),
	)

	switch level {
	case AuthNone:
		// No auth needed
	case AuthSecureChannel:
		// Open secure channel (pair on V1 if pairing password available)
		if !internal.IsSecureChannelV2(kc) && secrets.PairingPass != "" {
			if err := kc.AutoPairWithSecret(keycard.PairingPasswordToSecret(secrets.PairingPass)); err != nil {
				return err
			}
		}
		if err := kc.AutoOpenSecureChannel(); err != nil {
			return err
		}
		defer internal.AutoUnpair(kc)
	case AuthPIN:
		// Full auth: secure channel + PIN verification
		if !internal.IsSecureChannelV2(kc) && secrets.PairingPass != "" {
			if err := kc.AutoPairWithSecret(keycard.PairingPasswordToSecret(secrets.PairingPass)); err != nil {
				return err
			}
		}
		if err := kc.AutoOpenSecureChannel(); err != nil {
			return err
		}
		defer internal.AutoUnpair(kc)

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

// newCommandSet creates a keycard.CommandSet, optionally using a custom CA
// public key and/or whitelisted card identity key from CLI flags.
func newCommandSet(ch types.Channel, cmd *cli.Command) *keycard.CommandSet {
	cardCA := cmd.String("card-ca")
	whitelistCard := cmd.String("whitelist-card")

	if cardCA == "" && whitelistCard == "" {
		return keycard.NewCommandSet(ch)
	}

	var caPublicKeys [][33]byte
	var whitelistedCardKeys [][33]byte

	if cardCA != "" {
		caBytes, err := internal.ParseHex(cardCA)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: invalid card-ca hex: %v\n", err)
		} else if len(caBytes) != 33 {
			fmt.Fprintln(os.Stderr, "warning: card-ca must be 33 bytes (compressed public key)")
		} else {
			var caKey [33]byte
			copy(caKey[:], caBytes)
			caPublicKeys = append(caPublicKeys, caKey)
		}
	}

	if whitelistCard != "" {
		wlBytes, err := internal.ParseHex(whitelistCard)
		if err != nil {
			fmt.Fprintln(os.Stderr, "warning: invalid whitelist-card hex:", err)
		} else if len(wlBytes) != 33 {
			fmt.Fprintln(os.Stderr, "warning: whitelist-card must be 33 bytes (compressed public key)")
		} else {
			var wlKey [33]byte
			copy(wlKey[:], wlBytes)
			whitelistedCardKeys = append(whitelistedCardKeys, wlKey)
		}
	}

	return keycard.NewCommandSetWithCAs(ch, caPublicKeys, whitelistedCardKeys)
}
