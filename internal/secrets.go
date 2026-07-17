package internal

import (
	"fmt"
	"os"
)

const KeycardDefaultPairing = "KeycardDefaultPairing"

// Secrets holds resolved card credentials.
type Secrets struct {
	Pin         string
	Puk         string
	PairingPass string
}

// ResolveSecrets resolves secrets from CLI flags and environment variables.
// Priority: CLI flags > environment variables.
// Pairing password defaults to KeycardDefaultPairing if not provided.
func ResolveSecrets(pinFlag, pukFlag, pairingFlag string) *Secrets {
	secrets := &Secrets{}

	// 1. CLI flags
	if pinFlag != "" {
		secrets.Pin = pinFlag
	}
	if pukFlag != "" {
		secrets.Puk = pukFlag
	}
	if pairingFlag != "" {
		secrets.PairingPass = pairingFlag
	}

	// 2. Environment variables
	if secrets.Pin == "" {
		if v := os.Getenv("KEYCARD_PIN"); v != "" {
			secrets.Pin = v
		}
	}
	if secrets.Puk == "" {
		if v := os.Getenv("KEYCARD_PUK"); v != "" {
			secrets.Puk = v
		}
	}
	if secrets.PairingPass == "" {
		if v := os.Getenv("KEYCARD_PAIRING_PASSWORD"); v != "" {
			secrets.PairingPass = v
		}
	}

	// 3. Default pairing password
	if secrets.PairingPass == "" {
		secrets.PairingPass = KeycardDefaultPairing
	}

	return secrets
}

// RequirePIN returns an error if PIN is not set.
func RequirePIN(secrets *Secrets) error {
	if secrets.Pin == "" {
		return fmt.Errorf("PIN is required: provide --pin flag or KEYCARD_PIN environment variable")
	}
	return nil
}
