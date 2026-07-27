package internal

import (
	"fmt"
)

const KeycardDefaultPairing = "KeycardDefaultPairing"

// Secrets holds resolved card credentials.
type Secrets struct {
	Pin         string
	Puk         string
	PairingPass string
}

// ResolveSecrets resolves secrets from CLI flags.
// Priority: CLI flags > environment variables (handled by the CLI framework).
// Pairing password defaults to KeycardDefaultPairing if not provided.
func ResolveSecrets(pinFlag, pukFlag, pairingFlag string) *Secrets {
	secrets := &Secrets{}

	// CLI flags (env vars are already resolved by the CLI framework via Sources)
	secrets.Pin = pinFlag
	secrets.Puk = pukFlag
	secrets.PairingPass = pairingFlag

	// Default pairing password
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
