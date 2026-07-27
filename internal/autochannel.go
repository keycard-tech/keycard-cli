package internal

import (
	"github.com/ethereum/go-ethereum/log"
	keycard "github.com/keycard-tech/keycard-go/v4"
)

// SecureChannelVersion returns the secure channel version, or false if unknown.
func SecureChannelVersion(cs *keycard.CommandSet) (keycard.SecureChannelVersion, bool) {
	return cs.SecureChannelVersion()
}

// IsSecureChannelV2 checks if the card uses secure channel V2.
func IsSecureChannelV2(cs *keycard.CommandSet) bool {
	ver, ok := cs.SecureChannelVersion()
	return ok && ver == keycard.VersionV2
}

// AppVersion returns the applet version as uint16.
func AppVersion(cs *keycard.CommandSet) uint16 {
	info := cs.AppInfo()
	if info == nil {
		return 0
	}
	return info.AppVersion()
}

// IsAppletV4Plus checks if the applet version is 4.0 or higher.
func IsAppletV4Plus(cs *keycard.CommandSet) bool {
	return AppVersion(cs) >= 0x0400
}

// AutoAuth handles the full authentication flow:
// - V1: AutoPairWithSecret → AutoOpenSecureChannel → VerifyPIN
// - V2: AutoOpenSecureChannel → VerifyPIN (no pairing needed)
func AutoAuth(cs *keycard.CommandSet, secrets *Secrets) error {
	v2 := IsSecureChannelV2(cs)

	if !v2 && secrets.PairingPass != "" {
		log.Info("auto-pairing (V1)")
		if err := cs.AutoPairWithSecret(keycard.PairingPasswordToSecret(secrets.PairingPass)); err != nil {
			return err
		}
	}

	log.Info("opening secure channel")
	if err := cs.AutoOpenSecureChannel(); err != nil {
		return err
	}

	if secrets.Pin != "" {
		log.Info("verifying PIN")
		if err := cs.VerifyPIN(secrets.Pin); err != nil {
			return err
		}
	}

	return nil
}

func AutoUnpair(cs *keycard.CommandSet) error {
	if IsSecureChannelV2(cs) {
		return nil
	}
	pairing := cs.Pairing()
	if pairing == nil {
		return nil
	}
	log.Info("auto-unpairing", "index", pairing.Index())
	return cs.Unpair(pairing.Index())
}
