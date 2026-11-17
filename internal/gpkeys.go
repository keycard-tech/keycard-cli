package internal

import (
	"fmt"
	"strings"

	"github.com/keycard-tech/keycard-go/v4/globalplatform"
)

// GPKeyOptions returns the keycard-go options making a GlobalPlatform command set use
// the given static MAC key. An empty key yields no options, leaving keycard-go to offer
// the public development key sets.
//
// The key is passed as the ENC key too. Commands are only MACed, never encrypted, so the
// session encryption key derived from it is never used, but keycard-go requires an ENC
// key of the same length as the MAC one.
func GPKeyOptions(macKey string) ([]globalplatform.Option, error) {
	if macKey == "" {
		return nil, nil
	}

	key, err := ParseHex(macKey)
	if err != nil {
		return nil, fmt.Errorf("invalid gp-mac-key hex: %w", err)
	}

	keySets, err := gpKeySets(key)
	if err != nil {
		return nil, err
	}

	return []globalplatform.Option{globalplatform.WithKeySets(keySets...)}, nil
}

// gpKeySets returns the key sets the key material is valid for, SCP03 first.
//
// The card reports its Secure Channel Protocol in the INITIALIZE UPDATE response, so
// both are offered and the card decides. Order matters: an SCP02 key set sends the 8
// byte host challenge that a card in S16 mode rejects with 6700, and that rejection ends
// the whole negotiation instead of falling through to the next key set.
//
// A key set whose card cryptogram does not verify is dropped before EXTERNAL
// AUTHENTICATE is sent, so offering both protocols costs no authentication attempts.
func gpKeySets(key []byte) ([]globalplatform.KeySet, error) {
	candidates := []globalplatform.KeySet{
		globalplatform.NewSCP03KeySet(0, key, key, nil),
		globalplatform.NewSCP02KeySet(key),
	}

	var (
		keySets  []globalplatform.KeySet
		rejected []string
	)

	for _, candidate := range candidates {
		if err := candidate.Validate(); err != nil {
			rejected = append(rejected, err.Error())
			continue
		}

		keySets = append(keySets, candidate)
	}

	if len(keySets) == 0 {
		return nil, fmt.Errorf("key rejected by both protocols: %s", strings.Join(rejected, ", "))
	}

	return keySets, nil
}
